#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

const char *stop_word = "exit";

void handle_error(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

char is_alive(int PID)
{
    int retval = waitpid(PID, NULL, WNOHANG);
    return (retval > 0) ? 0 : 1;
}
