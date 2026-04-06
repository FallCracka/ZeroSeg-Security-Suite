#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>

class ZeroSegScanner {
public:
    ZeroSegScanner();
    void runScan(std::string ip);
private:
    void initDB();
    void logToDB(std::string ip, int port, std::string risk);
};

#endif