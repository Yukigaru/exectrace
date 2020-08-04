#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <cerrno>
#include <stdexcept>
#include <iostream>
#include <sys/user.h>
#include <sys/syscall.h>
#include <linux/limits.h>
#include <vector>
#include "trace_command.h"

static constexpr int PID_MYSELF = 0;

struct ExecveArgs {
    std::string path;
    std::vector<std::string> argv;
    //char *const __envp[];
};

std::string readProcessPath(pid_t pid, size_t addr) {
    char buf[PATH_MAX] = {0};
    size_t len = 0;
    bool done = false;

    while (!done) {
        auto val = ptrace(PTRACE_PEEKDATA, pid, addr + len);
        if (errno)
            break;

        for (size_t i = 0; i < sizeof(val); i++) {
            char c = *(reinterpret_cast<char *>(&val) + i);
            if (c != '\0') {
                buf[len + i] = c;
            } else {
                done = true;
                break;
            }
        }

        len += sizeof(val);
        // TODO: handle PATH_MAX exit
    }
    return std::string(buf);
}

ExecveArgs decodeExecve(pid_t pid, user_regs_struct &state) {
    ExecveArgs ret;

    // x86_64 syscall arguments:
    // 0) rdi
    // 1) rsi
    // 2) rdx
    // 3) r10
    // 4) r8
    // 5) r9
    auto arg0 = static_cast<size_t>(state.rdi);
    ret.path = readProcessPath(pid, arg0);

    return ret;
}

void traceCommand(const char *cmdLine, char *const argv[]) {
    pid_t pid = fork();
    if (pid == 0) {
        // child
        //char *const argv[] = {nullptr};
        long ret = ptrace(PTRACE_TRACEME, PID_MYSELF, nullptr, nullptr); // TODO: handle ret
        if (ret == -1) {
        }

        char *const envp[] = {nullptr};
        execve(cmdLine, argv, envp);

    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0); // TODO: ret

        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

        while (true) {
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
            waitpid(pid, &status, 0);

            if (WIFEXITED(status))
                break;
            if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
                break;

            user_regs_struct state = {0};
            ptrace(PTRACE_GETREGS, pid, 0, &state);

            if (state.orig_rax == SYS_execve) {
                ExecveArgs args = decodeExecve(pid, state);

                // ls -l
                // Process created: ls -l
                // Pid 1235 created a new process: ls -l
                // Pid 1235 created a new process pid 1235: ls -l
                // 3123235234: Pid 1235 created a new process pid 1235: ls -l
                std::cout << "Process created: " << args.path << std::endl;
            }

            // skip after syscall
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
            waitpid(pid, &status, 0);
        }

    } else {
        throw std::runtime_error("failed to fork the parent process, errno: " + std::to_string(errno));
    }
}