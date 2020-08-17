#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <cerrno>
#include <cstring> // memcpy
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

std::ostream & operator <<(std::ostream &os, ExecveArgs &ea) {
    bool space = false;
    for (const auto &v : ea.argv) {
        if (space)
            os << ' ';
        os << v;
        space = true;
    }
    return os;
}

size_t readProcessPointer(pid_t pid, size_t addr) {
    size_t result = 0;
    auto *resultPtr = reinterpret_cast<unsigned char *>(&result);

    size_t len = 0;
    size_t bytesLeft = sizeof(result);

    while (bytesLeft > 0) {
        auto val = ptrace(PTRACE_PEEKDATA, pid, addr + len);
        if (errno) {
            std::cerr << "Failed to peek data from pid " << pid << std::endl;
            break;
        }

        memcpy(resultPtr, &val, std::min(sizeof(val), bytesLeft));
        len += sizeof(val);
        bytesLeft -= sizeof(val);
    }

    return result;
}

std::string readProcessString(pid_t pid, size_t addr) {
    char buf[PATH_MAX] = {0};
    size_t len = 0;
    bool done = false;

    while (!done) {
        auto val = ptrace(PTRACE_PEEKDATA, pid, addr + len);
        if (errno) {
            std::cerr << "Failed to peek data from pid " << pid << std::endl;
            break;
        }

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

std::vector<std::string> readProcessStrings(pid_t pid, size_t addr) {
    std::vector<std::string> result;
    while (true) {
        size_t v_addr = readProcessPointer(pid, addr);
        if (!v_addr)
            break;

        auto s = readProcessString(pid, v_addr);
        result.push_back(s);
        addr += sizeof(void *);
    }

    return result;
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
    auto arg1 = static_cast<size_t>(state.rsi);
    ret.path = readProcessString(pid, arg0);
    ret.argv = readProcessStrings(pid, arg1);

    return ret;
}

void watchProcess(pid_t pid) {
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    while (true) {
        int status = 0;
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        waitpid(pid, &status, 0);

        if (WIFEXITED(status))
            break;
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
            break;

        user_regs_struct state = {0};
        ptrace(PTRACE_GETREGS, pid, 0, &state);

        if (state.orig_rax == SYS_vfork) {
            std::cerr << "forked " << std::endl;

        } else if (state.orig_rax == SYS_fork) {
            std::cerr << "forked " << std::endl;

        } else if (state.orig_rax == SYS_execve) {
            ExecveArgs args = decodeExecve(pid, state);

            // ls -l
            // Process created: ls -l
            // Pid 1235 created a new process: ls -l
            // Pid 1235 created a new process child_pid 1235: ls -l
            // 3123235234: Pid 1235 created a new process child_pid 1235: ls -l
            std::cerr << "Process created: " << args << std::endl;
        }

        // skip after syscall
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        waitpid(pid, &status, 0);
    }
}

void traceCommand(const char *cmdLine, char *const argv[]) {
    pid_t exectrace_pid = getpid();

    pid_t child_pid = fork();
    if (child_pid == 0) {
        // child
        //char *const argv[] = {nullptr};
        long ret = ptrace(PTRACE_TRACEME, PID_MYSELF, nullptr, nullptr); // TODO: handle ret
        if (ret == -1) {
        }

        char *const envp[] = {nullptr};
        execve(cmdLine, argv, envp);

    } else if (child_pid > 0) {
        // wait until the child changes its state
        int status;
        waitpid(child_pid, &status, 0); // TODO: ret

        std::cerr << "Pid " << exectrace_pid << " created pid " << child_pid << ":";
        size_t idx = 0;
        while (true) {
            const char *argStr = argv[idx];
            if (!argStr)
                break;
            std::cerr << ' ' << argStr;
            idx++;
        }
        std::cerr << std::endl;

        watchProcess(child_pid);
    } else {
        throw std::runtime_error("failed to fork the parent process, errno: " + std::to_string(errno));
    }
}