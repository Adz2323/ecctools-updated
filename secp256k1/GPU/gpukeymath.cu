#include "secp256k1.cuh"
#include "Point.cuh"
#include "Int.cuh"

#define GPU_BATCH_SIZE (1024 * 256)
#define THREADS_PER_BLOCK 256

struct GPUBatchBuffer
{
    Point *d_points;
    Point *d_results;
    Int *d_randoms;
    Point *h_results;
    Int *h_randoms;
    char **pubKeyHexes;
    char **decimalStrs;
    int batchSize;
};

__global__ void keySearchKernel(Point startPoint, Int *randoms,
                                Point *results, int count, Secp256K1_CUDA secp)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < count)
    {
        Point pubKey = secp.DeviceComputePublicKey(&randoms[idx]);
        results[idx] = secp.SubtractPoints(startPoint, pubKey);
    }
}

class GPUWorker
{
private:
    Secp256K1_CUDA secp;
    GPUBatchBuffer buffer;

public:
    GPUWorker(int batchSize = GPU_BATCH_SIZE)
    {
        secp.InitCUDA();
        buffer.batchSize = batchSize;

        cudaMalloc(&buffer.d_points, batchSize * sizeof(Point));
        cudaMalloc(&buffer.d_results, batchSize * sizeof(Point));
        cudaMalloc(&buffer.d_randoms, batchSize * sizeof(Int));

        buffer.h_results = new Point[batchSize];
        buffer.h_randoms = new Int[batchSize];
        buffer.pubKeyHexes = new char *[batchSize];
        buffer.decimalStrs = new char *[batchSize];

        for (int i = 0; i < batchSize; i++)
        {
            buffer.pubKeyHexes[i] = new char[67]; // 66 chars + null terminator
            buffer.decimalStrs[i] = new char[78]; // For decimal representation
        }
    }

    ~GPUWorker()
    {
        cudaFree(buffer.d_points);
        cudaFree(buffer.d_results);
        cudaFree(buffer.d_randoms);
        delete[] buffer.h_results;
        delete[] buffer.h_randoms;

        for (int i = 0; i < buffer.batchSize; i++)
        {
            delete[] buffer.pubKeyHexes[i];
            delete[] buffer.decimalStrs[i];
        }
        delete[] buffer.pubKeyHexes;
        delete[] buffer.decimalStrs;

        secp.Cleanup();
    }

    void processBatch(const Point &startPoint, const Int &rangeStart,
                      const Int &rangeEnd, bool &running, uint64_t &total_ops)
    {

        // Generate random values on CPU
        for (int i = 0; i < buffer.batchSize; i++)
        {
            buffer.h_randoms[i] = generate_random_range(rangeStart, rangeEnd);
        }

        // Copy to GPU
        cudaMemcpy(buffer.d_randoms, buffer.h_randoms,
                   buffer.batchSize * sizeof(Int), cudaMemcpyHostToDevice);

        // Launch kernel
        int blocks = (buffer.batchSize + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK;
        keySearchKernel<<<blocks, THREADS_PER_BLOCK>>>(
            startPoint, buffer.d_randoms, buffer.d_results, buffer.batchSize, secp);

        // Copy results back
        cudaMemcpy(buffer.h_results, buffer.d_results,
                   buffer.batchSize * sizeof(Point), cudaMemcpyDeviceToHost);

        // Process results
        for (int i = 0; i < buffer.batchSize && running; i++)
        {
            secp.GetPublicKeyHex(true, buffer.h_results[i], buffer.pubKeyHexes[i]);
            char *decimal = buffer.h_randoms[i].GetBase10();
            strcpy(buffer.decimalStrs[i], decimal);
            free(decimal);

            total_ops++;

            pthread_mutex_lock(&print_mutex);
            printf("\r%s - %s", buffer.pubKeyHexes[i], buffer.decimalStrs[i]);
            fflush(stdout);

            if (bloom_initialized1 && triple_bloom_check(buffer.pubKeyHexes[i]))
            {
                printf("\nMATCH FOUND!\n");
                printf("Public Key: %s\n", buffer.pubKeyHexes[i]);
                printf("Subtraction Value: %s\n", buffer.decimalStrs[i]);

                FILE *f = fopen("matches.txt", "a");
                if (f)
                {
                    fprintf(f, "Match Found\n");
                    fprintf(f, "Public Key: %s\n", buffer.pubKeyHexes[i]);
                    fprintf(f, "Subtraction: %s\n\n", buffer.decimalStrs[i]);
                    fclose(f);
                }
            }
            pthread_mutex_unlock(&print_mutex);
        }
    }
};

// Modified worker function for GPU processing
void *gpu_subtraction_worker(void *arg)
{
    ThreadArgs *args = (ThreadArgs *)arg;
    GPUWorker gpu_worker(GPU_BATCH_SIZE);

    while (args->running)
    {
        gpu_worker.processBatch(args->startPoint, args->rangeStart,
                                args->rangeEnd, args->running, args->total_ops);

        double elapsed = difftime(time(NULL), args->start_time);
        args->keys_per_second = args->total_ops / (elapsed > 0 ? elapsed : 1);

        usleep(100); // Prevent CPU overload
    }

    return NULL;
}
