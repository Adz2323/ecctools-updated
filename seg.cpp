#include <iostream>
#include <fstream>
#include <string>
#include <array>
#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <functional>
#include <algorithm>
#include <signal.h>
#include <chrono>
#include <unistd.h>
#include <sstream>
#include <iomanip>

class ThreadPool
{
private:
    using Task = std::function<void()>;

    std::vector<std::thread> workers;
    std::queue<Task> tasks;
    mutable std::mutex queue_mutex;
    std::mutex file_mutex;
    std::condition_variable condition;
    std::atomic<bool> stop{false};
    std::shared_ptr<std::ofstream> output_file;
    std::atomic<int> processed_count{0};
    std::atomic<int> active_tasks{0};
    std::atomic<bool> force_shutdown{false};

    static const size_t BUFFER_SIZE = 4096;
    std::vector<std::array<char, BUFFER_SIZE>> thread_buffers;

protected:
    bool processResult(const std::string &result, const std::string &decimal)
    {
        size_t pos = result.find("Result:");
        if (pos != std::string::npos)
        {
            std::string public_key = result.substr(pos + 7);
            public_key.erase(0, std::find_if(public_key.begin(), public_key.end(),
                                             [](unsigned char ch)
                                             { return !std::isspace(ch); }) -
                                    public_key.begin());
            public_key.erase(std::find_if(public_key.rbegin(), public_key.rend(),
                                          [](unsigned char ch)
                                          { return !std::isspace(ch); })
                                 .base(),
                             public_key.end());

            if (!public_key.empty())
            {
                {
                    std::lock_guard<std::mutex> lock(file_mutex);
                    if (output_file && output_file->is_open())
                    {
                        *output_file << public_key << ' ';
                        output_file->flush();
                    }
                }
                std::cout << "Processed " << ++processed_count << ": " << decimal << '\n';
                return true;
            }
        }
        return false;
    }

    void killProcess(const std::string &cmd)
    {
        std::stringstream ss;
        ss << "pkill -f \"" << cmd << "\"";
        system(ss.str().c_str());
    }

    void runCommand(const std::string &decimal, size_t thread_id)
    {
        if (thread_id >= thread_buffers.size() || stop.load() || force_shutdown.load())
            return;

        std::string cmd = "./Auto 02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16 - " + decimal;
        active_tasks++;

        FILE *pipe = nullptr;
        try
        {
            pipe = popen(cmd.c_str(), "r");
            if (!pipe)
            {
                active_tasks--;
                return;
            }

            std::string result;
            auto &buffer = thread_buffers[thread_id];
            bool found = false;
            auto start_time = std::chrono::steady_clock::now();

            while (!found && !stop.load() && !force_shutdown.load())
            {
                if (fgets(buffer.data(), buffer.size(), pipe) == nullptr)
                    break;
                result += buffer.data();
                found = processResult(result, decimal);

                auto current_time = std::chrono::steady_clock::now();
                if (std::chrono::duration_cast<std::chrono::seconds>(
                        current_time - start_time)
                        .count() > 10)
                {
                    std::cerr << "Process timeout for decimal: " << decimal << std::endl;
                    killProcess(cmd);
                    break;
                }
            }

            if (pipe)
            {
                pclose(pipe);
                pipe = nullptr;
            }
        }
        catch (...)
        {
            if (pipe)
                pclose(pipe);
            killProcess(cmd);
            active_tasks--;
            throw;
        }

        active_tasks--;
    }

public:
    ThreadPool(size_t numThreads, std::shared_ptr<std::ofstream> outFile)
        : output_file(std::move(outFile)), thread_buffers(numThreads)
    {
        try
        {
            workers.reserve(numThreads);
            for (size_t i = 0; i < numThreads; ++i)
            {
                workers.emplace_back([this, i]
                                     {
                    while (!force_shutdown.load()) {
                        Task task;
                        {
                            std::unique_lock<std::mutex> lock(queue_mutex);
                            condition.wait(lock, [this] { 
                                return force_shutdown.load() || stop.load() || !tasks.empty(); 
                            });
                            
                            if ((force_shutdown.load() || stop.load()) && tasks.empty()) {
                                return;
                            }
                            
                            if (!tasks.empty()) {
                                task = std::move(tasks.front());
                                tasks.pop();
                            }
                        }
                        
                        if (task && !force_shutdown.load()) {
                            try {
                                task();
                            }
                            catch (const std::exception& e) {
                                std::cerr << "Exception in thread " << i << ": " << e.what() << std::endl;
                            }
                            catch (...) {
                                std::cerr << "Unknown exception in thread " << i << std::endl;
                            }
                        }
                    } });
            }
        }
        catch (...)
        {
            forceShutdown();
            throw;
        }
    }

    bool isStopped() const
    {
        return stop.load();
    }

    int getActiveTaskCount() const
    {
        return active_tasks.load();
    }

    int getProcessedCount() const
    {
        return processed_count.load();
    }

    void enqueueCommand(const std::string &decimal, size_t thread_id)
    {
        if (!stop.load() && !force_shutdown.load())
        {
            enqueue([this, decimal, thread_id]()
                    { this->runCommand(decimal, thread_id); });
        }
    }

    template <class F>
    void enqueue(F &&f)
    {
        if (!stop.load() && !force_shutdown.load())
        {
            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                tasks.emplace(std::forward<F>(f));
            }
            condition.notify_one();
        }
    }

    void forceShutdown()
    {
        force_shutdown.store(true);
        stop.store(true);

        // Kill all running Auto processes
        system("pkill -f \"./Auto\"");

        condition.notify_all();

        for (auto &worker : workers)
        {
            if (worker.joinable())
            {
                try
                {
                    worker.join();
                }
                catch (...)
                {
                    // Ignore any join errors during force shutdown
                }
            }
        }

        workers.clear();
    }

    void shutdown()
    {
        if (!force_shutdown.load())
        {
            stop.store(true);
            condition.notify_all();

            // Give threads a chance to finish gracefully
            std::this_thread::sleep_for(std::chrono::seconds(1));

            if (active_tasks.load() > 0)
            {
                forceShutdown();
            }
            else
            {
                for (auto &worker : workers)
                {
                    if (worker.joinable())
                    {
                        worker.join();
                    }
                }
            }
        }
    }

    ~ThreadPool()
    {
        forceShutdown();
    }
};

// Global signal handler
ThreadPool *g_pool = nullptr;

void signal_handler(int signum)
{
    if (g_pool)
    {
        std::cout << "\nReceived signal " << signum << ". Shutting down...\n";
        g_pool->forceShutdown();
    }
    exit(signum);
}

int main()
{
    std::ifstream inFile("decimals.txt", std::ios::in | std::ios::binary);
    auto outFile = std::make_shared<std::ofstream>("publickeys.txt", std::ios::app);

    if (!inFile || !*outFile)
    {
        std::cerr << "Error opening files\n";
        return 1;
    }

    // Get file size
    inFile.seekg(0, std::ios::end);
    std::streamsize file_size = inFile.tellg();
    inFile.seekg(0, std::ios::beg);

    if (file_size == -1)
    {
        std::cerr << "Error getting file size\n";
        return 1;
    }

    std::cout << "Input file size: " << file_size << " bytes\n";

    unsigned int numThreads = std::thread::hardware_concurrency();
    if (numThreads == 0)
        numThreads = 4;
    numThreads = std::min(std::max(1u, numThreads), 8u);

    try
    {
        ThreadPool pool(numThreads, outFile);
        g_pool = &pool;

        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);

        std::cout << "Starting processing with " << numThreads << " threads...\n";

        const size_t CHUNK_SIZE = 8192;
        std::vector<char> buffer(CHUNK_SIZE);
        std::string line_buffer;
        size_t current_thread = 0;
        std::streamsize total_bytes_read = 0;
        size_t lines_processed = 0;

        auto last_progress = std::chrono::steady_clock::now();
        auto last_activity = std::chrono::steady_clock::now();
        int last_processed = 0;
        int stall_count = 0;
        bool eof_reached = false;

        while (!pool.isStopped() && !eof_reached)
        {
            // Read chunk
            inFile.read(buffer.data(), buffer.size());
            std::streamsize bytes_read = inFile.gcount();

            if (bytes_read == 0)
            {
                if (inFile.eof())
                {
                    eof_reached = true;
                    std::cout << "Reached end of file\n";
                }
                else
                {
                    std::cerr << "Error reading file\n";
                    break;
                }
            }

            total_bytes_read += bytes_read;
            line_buffer.append(buffer.data(), bytes_read);

            size_t pos = 0;
            size_t next_pos;

            while ((next_pos = line_buffer.find('\n', pos)) != std::string::npos)
            {
                std::string decimal = line_buffer.substr(pos, next_pos - pos);
                if (!decimal.empty())
                {
                    decimal.erase(0, std::find_if(decimal.begin(), decimal.end(),
                                                  [](unsigned char ch)
                                                  { return !std::isspace(ch); }) -
                                         decimal.begin());
                    decimal.erase(std::find_if(decimal.rbegin(), decimal.rend(),
                                               [](unsigned char ch)
                                               { return !std::isspace(ch); })
                                      .base(),
                                  decimal.end());

                    if (!decimal.empty())
                    {
                        pool.enqueueCommand(decimal, current_thread);
                        current_thread = (current_thread + 1) % numThreads;
                        lines_processed++;
                    }
                }
                pos = next_pos + 1;
            }
            line_buffer.erase(0, pos);

            // Print progress and check for stalls
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_progress).count() >= 5)
            {
                double progress = (static_cast<double>(total_bytes_read) / file_size) * 100;
                int current_processed = pool.getProcessedCount();

                std::cout << "Progress: " << std::fixed << std::setprecision(2) << progress
                          << "% (" << lines_processed << " lines read, "
                          << current_processed << " processed, "
                          << pool.getActiveTaskCount() << " active)\n";

                // Check for stalls
                if (current_processed == last_processed)
                {
                    if (std::chrono::duration_cast<std::chrono::seconds>(now - last_activity).count() > 30)
                    {
                        stall_count++;
                        std::cout << "No progress detected (" << stall_count << " times)\n";
                        if (stall_count >= 3)
                        {
                            std::cout << "Multiple stalls detected, forcing shutdown...\n";
                            pool.forceShutdown();
                            break;
                        }
                        last_activity = now;
                    }
                }
                else
                {
                    stall_count = 0;
                    last_activity = now;
                }

                last_processed = current_processed;
                last_progress = now;
            }

            // Small sleep to prevent CPU overload
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        // Process any remaining data in line_buffer
        if (!line_buffer.empty())
        {
            std::string decimal = line_buffer;
            decimal.erase(0, std::find_if(decimal.begin(), decimal.end(),
                                          [](unsigned char ch)
                                          { return !std::isspace(ch); }) -
                                 decimal.begin());
            decimal.erase(std::find_if(decimal.rbegin(), decimal.rend(),
                                       [](unsigned char ch)
                                       { return !std::isspace(ch); })
                              .base(),
                          decimal.end());

            if (!decimal.empty())
            {
                pool.enqueueCommand(decimal, current_thread);
                lines_processed++;
            }
        }

        std::cout << "\nFile reading complete. Processed " << lines_processed << " lines.\n";
        std::cout << "Waiting for remaining tasks to complete...\n";

        // Wait for remaining tasks with a timeout
        auto shutdown_start = std::chrono::steady_clock::now();
        while (pool.getActiveTaskCount() > 0)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::steady_clock::now() - shutdown_start)
                               .count();

            if (elapsed > 30)
            {
                std::cout << "Timeout waiting for tasks to complete. Forcing shutdown...\n";
                pool.forceShutdown();
                break;
            }
        }

        pool.shutdown();
        g_pool = nullptr;

        std::cout << "Processing complete. Total lines processed: " << lines_processed << "\n";
        std::cout << "Total results generated: " << pool.getProcessedCount() << "\n";
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    catch (...)
    {
        std::cerr << "Unknown error occurred" << std::endl;
        return 1;
    }

    return 0;
}
