#include "trace_command.h"
#include <iostream>
#include <stdexcept>

int printHelp() {
    std::cout << "exectrace" << std::endl;
    return 0;
}

int main(int argc, char *const argv[]) {
    if (argc == 1)
        return printHelp();

    try {
        traceCommand(argv[1], &argv[1]);

    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
