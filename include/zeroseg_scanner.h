#ifndef ZEROSEG_SCANNER_H
#define ZEROSEG_SCANNER_H

#include <string>
#include <vector>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

class ZeroSegScanner {
private:
    std::vector<std::string> vuln_ports;
public:
    ZeroSegScanner();
    ~ZeroSegScanner();
    void initConsole();
    void showLegalInfo();
    void managePorts();
    void manageSites();
};

#endif
