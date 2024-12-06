#include <iostream>
#include <Winsock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <pcap.h>
#include <array>
#include <string>
#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable : 4996)

#define _WINSOCK_DEPRECATED_NO_WARNINGS

// ANSI 转义码
#define COLOR_RESET "\033[0m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_CYAN "\033[36m"
#define COLOR_MAGENTA "\033[35m"

using namespace std;

void printMAC(const array<BYTE, 6>& MAC) {
    for (int i = 0; i < 6; ++i)
        printf("%02x%c", MAC[i], (i < 5) ? ':' : '\n');
}

void printIP(DWORD IP) {
    BYTE* p = reinterpret_cast<BYTE*>(&IP);
    for (int i = 0; i < 4; ++i) {
        cout << static_cast<int>(p[i]);
        if (i < 3) cout << ".";
    }
    cout << endl;
}

#pragma pack(1)
struct FrameHeader_t {
    array<BYTE, 6> DesMAC;
    array<BYTE, 6> SrcMAC;
    WORD FrameType;
};

struct ARPFrame_t {
    FrameHeader_t FrameHeader;
    WORD HardwareType;
    WORD ProtocolType;
    BYTE HLen;
    BYTE PLen;
    WORD Operation;
    array<BYTE, 6> SendHa;
    DWORD SendIP;
    array<BYTE, 6> RecvHa;
    DWORD RecvIP;
};

void sendARPPacket(pcap_t* pcap_handle, const string& srcIP, const array<BYTE, 6>& srcMAC, const string& targetIP, array<BYTE, 6>& targetMAC) {
    ARPFrame_t ARPRequest{};
    ARPRequest.FrameHeader.DesMAC.fill(0xFF);  // 广播地址
    ARPRequest.FrameHeader.SrcMAC = srcMAC;
    ARPRequest.SendHa = srcMAC;
    ARPRequest.FrameHeader.FrameType = htons(0x0806);
    ARPRequest.HardwareType = htons(0x0001);
    ARPRequest.ProtocolType = htons(0x0800);
    ARPRequest.HLen = 6;
    ARPRequest.PLen = 4;
    ARPRequest.Operation = htons(0x0001);
    ARPRequest.SendIP = inet_addr(srcIP.c_str());
    ARPRequest.RecvIP = inet_addr(targetIP.c_str());

    if (pcap_sendpacket(pcap_handle, reinterpret_cast<const u_char*>(&ARPRequest), sizeof(ARPFrame_t)) != -1) {
        cout << COLOR_GREEN << "ARP请求发送成功" << COLOR_RESET << endl;
    }

    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    while (pcap_next_ex(pcap_handle, &pkt_header, &pkt_data) != -1) {
        auto ARPReply = reinterpret_cast<const ARPFrame_t*>(pkt_data);
        if (ARPReply->RecvIP == ARPRequest.SendIP && ARPReply->SendIP == ARPRequest.RecvIP && ARPReply->Operation == htons(0x0002)) {
            cout << COLOR_YELLOW << "成功捕获到ARP并解析" << COLOR_RESET << endl;
            cout << COLOR_CYAN;
            printIP(ARPReply->SendIP);
            cout << " -> ";
            printMAC(ARPReply->SendHa);
            cout << COLOR_RESET;
            targetMAC = ARPReply->SendHa;
            return;
        }
    }
    cerr << COLOR_RED << "捕获数据包时发生错误" << COLOR_RESET << endl;
}

int main() {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << COLOR_RED << "获取网络接口时发生错误：" << errbuf << COLOR_RESET << endl;
        return 1;
    }

    array<pcap_if_t*, 100> interfaces{};
    int index = 0;
    for (pcap_if_t* ptr = alldevs; ptr; ptr = ptr->next) {
        for (pcap_addr_t* a = ptr->addresses; a; a = a->next) {
            if (a->addr->sa_family == AF_INET) {
                interfaces[index++] = ptr;
                cout << COLOR_MAGENTA << index << ". " << ptr->description << COLOR_RESET << endl;
                cout << "    " << COLOR_CYAN << "IP地址：" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << COLOR_RESET << endl;
                break;
            }
        }
    }

    int num;
    cout << COLOR_CYAN << "请选择要打开的网络适配器：" << COLOR_RESET;
    cin >> num;
    if (num <= 0 || num > index) {
        cerr << COLOR_RED << "无效序号" << COLOR_RESET << endl;
        return 1;
    }

    pcap_t* pcap_handle = pcap_open(interfaces[num - 1]->name, 1024, PCAP_OPENFLAG_PROMISCUOUS, 1000, nullptr, errbuf);
    if (!pcap_handle) {
        cerr << COLOR_RED << "打开网络适配器时发生错误：" << errbuf << COLOR_RESET << endl;
        return 1;
    }

    cout << COLOR_GREEN << "成功打开" << interfaces[num - 1]->description << COLOR_RESET << endl;

    u_int netmask = ((sockaddr_in*)(interfaces[num - 1]->addresses->netmask))->sin_addr.S_un.S_addr;
    bpf_program fcode;
    const char packet_filter[] = "arp";
    if (pcap_compile(pcap_handle, &fcode, packet_filter, 1, netmask) < 0 || pcap_setfilter(pcap_handle, &fcode) < 0) {
        cerr << COLOR_RED << "无法编译或设置数据包过滤器" << COLOR_RESET << endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    string LocalIP = inet_ntoa(((struct sockaddr_in*)(interfaces[num - 1]->addresses->addr))->sin_addr);
    array<BYTE, 6> cheatMAC = { 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 };
    array<BYTE, 6> LocalMAC{};
    array<BYTE, 6> TargetMAC{};
    sendARPPacket(pcap_handle, "112.112.112.112", cheatMAC, LocalIP, LocalMAC);

    string TargetIP;
    while (true) {
        cout << COLOR_CYAN << "请输入请求的IP地址：" << COLOR_RESET;
        cin >> TargetIP;
        sendARPPacket(pcap_handle, LocalIP, LocalMAC, TargetIP, TargetMAC);
    }

    pcap_freealldevs(alldevs);
    pcap_close(pcap_handle);
    
    return 0;
}
