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

class ThreadPool
{
private:
    using Task = std::function<void()>;

    std::vector<std::thread> workers;
    std::queue<Task> tasks;
    std::mutex queue_mutex;
    std::mutex file_mutex;
    std::condition_variable condition;
    bool stop;
    std::shared_ptr<std::ofstream> output_file;
    std::atomic<int> processed_count{0};

    static const size_t BUFFER_SIZE = 4096;
    std::vector<std::array<char, BUFFER_SIZE>> thread_buffers;

protected:
    void processResult(const std::string &result, const std::string &decimal)
    {
        size_t pos = result.find("Result:");
        if (pos != std::string::npos)
        {
            std::string public_key = result.substr(pos + 7);
            // Trim whitespace
            while (!public_key.empty() && std::isspace(public_key.front()))
            {
                public_key.erase(0, 1);
            }
            while (!public_key.empty() && std::isspace(public_key.back()))
            {
                public_key.erase(public_key.length() - 1);
            }

            if (!public_key.empty())
            {
                {
                    std::lock_guard<std::mutex> lock(file_mutex);
                    *output_file << public_key << ' ';
                    output_file->flush();
                }
                std::cout << "Processed " << ++processed_count << ": " << decimal << '\n';
            }
        }
    }

    void runCommand(const std::string &decimal, size_t thread_id)
    {
        std::string cmd = "./Auto 02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16 - " + decimal;

        FILE *pipe = popen(cmd.c_str(), "r");
        if (!pipe)
            return;

        std::string result;
        auto &buffer = thread_buffers[thread_id];

        while (fgets(buffer.data(), buffer.size(), pipe) != nullptr)
        {
            result += buffer.data();
            processResult(result, decimal);
        }

        pclose(pipe);
    }

public:
    ThreadPool(size_t numThreads, std::shared_ptr<std::ofstream> outFile)
        : stop(false), output_file(std::move(outFile)), thread_buffers(numThreads)
    {
        workers.reserve(numThreads);
        for (size_t i = 0; i < numThreads; ++i)
        {
            workers.emplace_back([this, i]
                                 {
                while (true) {
                    Task task;
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex);
                        condition.wait(lock, [this] { return stop || !tasks.empty(); });
                        if (stop && tasks.empty()) return;
                        
                        task = std::move(tasks.front());
                        tasks.pop();
                    }
                    task();
                } });
        }
    }

    void enqueueCommand(std::string decimal, size_t thread_id)
    {
        enqueue([this, decimal, thread_id]()
                { this->runCommand(decimal, thread_id); });
    }

    template <class F>
    void enqueue(F &&f)
    {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            tasks.emplace(std::forward<F>(f));
        }
        condition.notify_one();
    }

    ~ThreadPool()
    {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for (auto &worker : workers)
        {
            worker.join();
        }
    }
};

int main()
{
    std::ifstream inFile("decimals.txt", std::ios::in | std::ios::binary);
    auto outFile = std::make_shared<std::ofstream>("publickeys.txt");

    if (!inFile || !*outFile)
    {
        std::cerr << "Error opening files\n";
        return 1;
    }

    unsigned int numThreads = std::thread::hardware_concurrency();
    if (numThreads == 0)
        numThreads = 4;
    numThreads = std::min(std::max(1u, numThreads), 8u); // Between 1 and 8 threads

    ThreadPool pool(numThreads, outFile);
    std::string decimal;

    std::cout << "Starting processing with " << numThreads << " threads...\n";

    // Read file in larger chunks for better I/O performance
    const size_t CHUNK_SIZE = 8192;
    std::vector<char> buffer(CHUNK_SIZE);
    std::string line_buffer;
    size_t current_thread = 0;

    while (inFile.read(buffer.data(), buffer.size()) || inFile.gcount())
    {
        size_t count = inFile.gcount();
        line_buffer.append(buffer.data(), count);

        size_t pos = 0;
        size_t next_pos;

        while ((next_pos = line_buffer.find('\n', pos)) != std::string::npos)
        {
            decimal = line_buffer.substr(pos, next_pos - pos);
            if (!decimal.empty())
            {
                // Trim in-place
                while (!decimal.empty() && std::isspace(decimal.front()))
                {
                    decimal.erase(0, 1);
                }
                while (!decimal.empty() && std::isspace(decimal.back()))
                {
                    decimal.pop_back();
                }

                if (!decimal.empty())
                {
                    pool.enqueueCommand(decimal, current_thread);
                    current_thread = (current_thread + 1) % numThreads;
                }
            }
            pos = next_pos + 1;
        }
        line_buffer.erase(0, pos);
    }

    return 0;
}
