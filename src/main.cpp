#include "../include/zeroseg_scanner.h"
#include <iostream>

int main() {
    ZeroSegScanner scanner;
    scanner.initConsole();
    scanner.showLegalInfo();
    
    scanner.managePorts();
    scanner.manageSites();
    
    std::cout << "\n[OK] Сессия завершена.\n";
    return 0;
}
