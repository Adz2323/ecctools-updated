#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

#define MAX_CMD_LENGTH 1024

// Global flag for signal handling
volatile sig_atomic_t stop_flag = 0;

void signal_handler(int signum)
{
    if (signum == SIGINT)
    {
        printf("\n[+] Caught interrupt signal, cleaning up...\n");
        stop_flag = 1;
    }
}

int run_command(const char *cmd)
{
    printf("[+] Executing: %s\n", cmd);
    return system(cmd);
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

        // Run keydivision with -k option
        snprintf(div_cmd, MAX_CMD_LENGTH,
                 "./div --autosub %s %s -t 16 -k",
                 argv[1], argv[2]);

        if (run_command(div_cmd) != 0)
        {
            printf("[E] Error running keydivision\n");
            break; // Stop the program on error
        }

        if (stop_flag)
            break;

        // Run keyhunt
        snprintf(keyhunt_cmd, MAX_CMD_LENGTH,
                 "./keyhunt -m xpoint -f 135.txt -r 1:ffffffffff -t 16 -l compress");

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
        iteration++;
    }

    if (stop_flag)
    {
        printf("[+] Program terminated by user\n");
    }

    return 0;
}
