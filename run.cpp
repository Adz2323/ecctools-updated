#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/types.h>

#define MAX_CMD_LENGTH 1024

// Global flag for signal handling
volatile sig_atomic_t stop_flag = 0;
pid_t child_pid = -1; // Global to track subprocesses

void signal_handler(int signum)
{
    if (signum == SIGINT)
    {
        printf("\n[+] Caught interrupt signal, cleaning up...\n");
        stop_flag = 1;
        if (child_pid > 0)
        {
            kill(child_pid, SIGKILL); // Terminate child process
        }
    }
}

int run_command(const char *cmd)
{
    child_pid = fork();
    if (child_pid == 0)
    {
        // Child process
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        perror("[E] Failed to execute command");
        exit(1);
    }
    else if (child_pid > 0)
    {
        // Parent process
        int status;
        waitpid(child_pid, &status, 0);
        child_pid = -1; // Reset child_pid after process ends
        return WEXITSTATUS(status);
    }
    else
    {
        perror("[E] Fork failed");
        return 1;
    }
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        printf("Usage: %s <input_pubkey> <target_pubkey>\n", argv[0]);
        return 1;
    }

    // Set up signal handling
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);

    char div_cmd[MAX_CMD_LENGTH];
    char keyhunt_cmd[MAX_CMD_LENGTH];
    int iteration = 1;

    while (!stop_flag)
    {
        printf("\n[+] Starting iteration %d\n", iteration);

        // Run keydivision with spiral mode and -k option
        snprintf(div_cmd, MAX_CMD_LENGTH,
                 "./div --spiral %s %s -t 16 -k",
                 argv[1], argv[2]);

        if (run_command(div_cmd) != 0)
        {
            printf("[E] Error running keydivision\n");
            break;
        }

        if (stop_flag)
            break;

        // Run keyhunt - unchanged as it still uses the same 135.txt file
        snprintf(keyhunt_cmd, MAX_CMD_LENGTH,
                 "./keyhunt -m xpoint -f 135.txt -r 1:3fffffff -t 16 -l compress");

        int ret = run_command(keyhunt_cmd);

        if (stop_flag)
            break;

        // Check if keyhunt found a match
        FILE *keyhunt_output = fopen("KEYFOUNDKEYFOUND.txt", "r");
        if (keyhunt_output != NULL)
        {
            printf("\n[+] Match found!\n");
            char line[256];
            while (fgets(line, sizeof(line), keyhunt_output))
            {
                printf("%s", line);
            }
            fclose(keyhunt_output);
            break;
        }

        printf("[+] No match found in iteration %d, continuing...\n", iteration);
        // Remove the binary subtraction store file after each iteration
        remove("spiral_subtractions.bin");
        iteration++;
    }

    if (stop_flag)
    {
        printf("[+] Program terminated by user\n");
        // Clean up the binary subtraction store if interrupted
        remove("spiral_subtractions.bin");
    }

    return 0;
}
