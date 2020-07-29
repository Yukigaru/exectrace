#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <stdexcept>
#include <iostream>

#include "trace_command.h"

void traceCommand(const char *cmdLine, char *const argv[]) {
    std::cout << "Running command: " << cmdLine << std::endl;

    pid_t pid = fork();
    if (pid == 0) {
        // child
        //char *const argv[] = {nullptr};
        char *const envp[] = {nullptr};
        execve(cmdLine, argv, envp);

    } else if (pid > 0) {
        // the caller process
        pid_t wpid = waitpid(pid, nullptr, 0); // TODO: handle return value
        if (wpid == -1)
            throw std::runtime_error("failed to wait for the child process, errno: " + std::to_string(errno));
    } else {
        throw std::runtime_error("failed to fork the parent process, errno: " + std::to_string(errno));
    }
}