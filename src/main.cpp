#include "../include/zeroseg_scanner.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: ./zeroseg_linux <target_ip>" << std::endl;
        return 1;
    }
    ZeroSegScanner auditor;
    auditor.runScan(argv[1]);
    return 0;
}
