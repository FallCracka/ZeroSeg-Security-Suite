#include "../include/zeroseg_scanner.h"
#include <iostream>
#include <cstdlib>

ZeroSegScanner::ZeroSegScanner() {
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
}

ZeroSegScanner::~ZeroSegScanner() {
#ifdef _WIN32
    WSACleanup();
#endif
}

void ZeroSegScanner::initConsole() {
    std::cout << "\033[1;34m[ZEROSEG] Cross-Platform Suite v10.0\033[0m\n";
}

void ZeroSegScanner::showLegalInfo() {
    std::cout << "\n\033[1;33m[НОРМАТИВНАЯ БАЗА]\033[0m\n";
    std::cout << "РФ: ФЗ-187 (КИИ), ФЗ-152 (ПДн), Приказы ФСТЭК №17/21\n";
}

void ZeroSegScanner::managePorts() {
    std::string act;
    std::cout << "\n[ПОРТЫ] Блокировать уязвимые порты (21, 445)? [b]lock / [u]nblock: "; 
    std::cin >> act;
    
    std::vector<std::string> ports = {"21", "445"};
    for (const auto& p : ports) {
        std::string cmd;
        if (act == "b") {
#ifdef _WIN32
            cmd = "netsh advfirewall firewall add rule name=\"ZeroSeg_Port_" + p + "\" protocol=TCP localport=" + p + " action=block dir=IN";
#else
            cmd = "sudo iptables -A INPUT -p tcp --dport " + p + " -j DROP";
#endif
        } else if (act == "u") {
#ifdef _WIN32
            cmd = "netsh advfirewall firewall delete rule name=\"ZeroSeg_Port_" + p + "\"";
#else
            cmd = "sudo iptables -D INPUT -p tcp --dport " + p + " -j DROP 2>/dev/null";
#endif
        }
        if (!cmd.empty()) system(cmd.c_str());
    }
}

void ZeroSegScanner::manageSites() {
    std::string act;
    std::string ip = "149.154.167.92"; // Telegram IP для теста
    std::cout << "[САЙТЫ] Управление доступом к IP " << ip << " [b]lock / [u]nblock: ";
    std::cin >> act;

    std::string cmd;
    if (act == "b") {
#ifdef _WIN32
        cmd = "netsh advfirewall firewall add rule name=\"ZeroSeg_IP\" remoteip=" + ip + " action=block dir=OUT";
#else
        cmd = "sudo iptables -A OUTPUT -d " + ip + " -j REJECT";
#endif
    } else if (act == "u") {
#ifdef _WIN32
        cmd = "netsh advfirewall firewall delete rule name=\"ZeroSeg_IP\"";
#else
        cmd = "sudo iptables -D OUTPUT -d " + ip + " -j REJECT 2>/dev/null";
#endif
    }
    if (!cmd.empty()) system(cmd.c_str());
}
