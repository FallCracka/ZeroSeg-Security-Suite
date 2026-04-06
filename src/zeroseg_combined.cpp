#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <map>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <filesystem>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <sys/utsname.h>
#endif

namespace fs = std::filesystem;

struct ComplianceInfo {
    std::string law;
    std::string cert;
    std::string threat;
};

class ZeroSegEDR {
private:
    std::string machine_ip;
    std::string os_info;
    std::map<int, ComplianceInfo> kb;
    std::vector<std::pair<std::string, std::string>> active_blocks;

    void detectSystem() {
#ifdef _WIN32
        os_info = "Windows OS";
#else
        struct utsname buffer;
        if (uname(&buffer) == 0) os_info = std::string(buffer.sysname) + " " + buffer.release;
        else os_info = "Linux-Generic";
#endif
    }

    std::string getIP() {
        char host[256]; gethostname(host, sizeof(host));
        struct hostent* h = gethostbyname(host);
        return (h) ? inet_ntoa(*(struct in_addr*)*h->h_addr_list) : "127.0.0.1";
    }

    // Принудительный разрыв текущих соединений (требует conntrack-tools)
    void flushConnections() {
        #ifndef _WIN32
        system("sudo conntrack -F 2>/dev/null");
        #endif
    }

    bool isPortOpen(int port) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) return false;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(machine_ip.c_str());
        struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 100000;
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
        bool open = (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0);
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
        return open;
    }

    void setFirewall(std::string target, std::string type, bool block) {
        std::string cmd;
#ifndef _WIN32
        std::string action = block ? "-A" : "-D";
        std::string target_action = block ? "REJECT" : "ACCEPT";

        if (type == "PORT") {
            cmd = "sudo iptables " + action + " INPUT -p tcp --dport " + target + " -j " + (block ? "DROP" : "ACCEPT");
        } else if (type == "WEB" || type == "VPN") {
            // Для сайтов блокируем и входящий и исходящий трафик
            cmd = "sudo iptables " + action + " OUTPUT -d " + target + " -j REJECT && ";
            cmd += "sudo iptables " + action + " INPUT -s " + target + " -j REJECT";
        }
        
        if (!cmd.empty()) {
            system((cmd + " 2>/dev/null").c_str());
            flushConnections(); // Выбиваем текущую сессию
        }
#endif
        if (block) active_blocks.push_back({type, target});
    }

    std::string getReportName() {
        time_t now = time(0);
        tm *ltm = localtime(&now);
        std::stringstream ss;
        ss << (1900 + ltm->tm_year) << "-" << std::setfill('0') << std::setw(2) << (1 + ltm->tm_mon) << "-" << std::setw(2) << ltm->tm_mday;
        std::string date_str = ss.str();
        fs::create_directories("reports");
        int v = 1;
        while (true) {
            std::string name = "reports/REP_" + machine_ip + "_" + date_str + "_v" + std::to_string(v) + ".txt";
            if (!fs::exists(name)) return name;
            v++;
        }
    }

public:
    ZeroSegEDR() {
#ifdef _WIN32
        WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
        detectSystem();
        machine_ip = getIP();
        kb[21] = {"ФСТЭК №17", "ISO 27001", "FTP: Риск перехвата учетных данных"};
        kb[22] = {"ГОСТ Р 57580", "NIST", "SSH: Риск несанкционированного управления"};
        kb[80] = {"152-ФЗ (ПДн)", "PCI DSS", "HTTP: Утечка персональных данных"};
        kb[445] = {"ФСТЭК №239 (КИИ)", "ГОСТ", "SMB: Критический риск WannaCry"};
        kb[3389] = {"СТО БР ИББС", "ISO 27002", "RDP: Риск Brute-force атак"};
    }

    void run() {
        std::string filename = getReportName();
        std::cout << "\n[ ZeroSeg XDR: " << filename << " ]\n" << std::string(50, '=') << "\n";

        std::vector<std::string> log;
        log.push_back("ПРОТОКОЛ АУДИТА: " + filename);
        log.push_back("СИСТЕМА: " + os_info + " | IP: " + machine_ip + "\n");

        // 1. ПОРТЫ
        for (auto const& [port, info] : kb) {
            std::cout << "[*] Проверка порта " << port << "... ";
            if (isPortOpen(port)) {
                std::cout << "НАРУШЕНИЕ!\n    Блокировать? (y/n): "; char c; std::cin >> c;
                if(c == 'y') {
                    setFirewall(std::to_string(port), "PORT", true);
                    log.push_back("ПОРТ " + std::to_string(port) + " | ЗАБЛОКИРОВАН");
                }
            } else {
                std::cout << "ОК.\n";
            }
        }

        // 2. РЕАЛЬНАЯ БЛОКИРОВКА СЕРВИСОВ
        std::cout << "\n[*] Блокировка Shadow IT (Telegram/VPN/Web)...\n";
        
        // Блокируем основные домены и IP Telegram для надежности
        setFirewall("telegram.org", "WEB", true);
        setFirewall("149.154.160.0/20", "WEB", true); // Подсеть Telegram
        setFirewall("91.108.4.0/22", "WEB", true);    // Подсеть Telegram
        setFirewall("vpngate.net", "VPN", true);
        
        log.push_back("SHADOW IT: Блокировка telegram.org и vpngate.net активирована.");

        saveAndSync(log, filename);

        // 3. ОТКАТ
        std::cout << "\n=== СЕКТОР УПРАВЛЕНИЯ (ОТКАТ) ===\n";
        char q;
        std::cout << "[?] Вернуть доступ ко ВСЕМУ? (y/n): "; std::cin >> q;
        if (q == 'y') {
            rollback("PORT");
            rollback("WEB");
            rollback("VPN");
        }
    }

    void rollback(std::string type) {
        for (auto it = active_blocks.begin(); it != active_blocks.end(); ) {
            if (it->first == type) {
                setFirewall(it->second, it->first, false);
                it = active_blocks.erase(it);
            } else { ++it; }
        }
        std::cout << "[+] Откат для: " << type << "\n";
    }

    void saveAndSync(std::vector<std::string>& log_data, std::string path) {
        std::ofstream f(path);
        f << "=== ZeroSeg XDR SECURITY AUDIT REPORT ===\n";
        for (const auto& l : log_data) f << l << "\n";
        f.close();
        system("./sync_reports.sh");
    }
};

int main() {
    ZeroSegEDR edr;
    edr.run();
    return 0;
}
