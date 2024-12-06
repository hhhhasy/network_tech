#include "pcap.h"
#include<iostream>
#include<WinSock2.h>
#include<iomanip>
#include<cstring>
#include<sstream>
#include<chrono>  // 用于时间戳

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"WS2_32.lib")
using namespace std;

// 颜色控制代码
#define RESET       "\033[0m"
#define RED         "\033[31m"
#define GREEN       "\033[32m"
#define YELLOW      "\033[33m"
#define CYAN        "\033[36m"
#define BOLD        "\033[1m"

#pragma pack(1)
typedef struct FrameHeader_t {
    BYTE DesMAC[6];     // 目标MAC地址
    BYTE SrcMAC[6];     // 源MAC地址
    WORD FrameType;     // 帧类型
} FrameHeader_t;

typedef struct IPHeader_t {
    BYTE Ver_HLen;      // 版本和首部长度
    BYTE TOS;           // 服务类型
    WORD TotalLen;      // 总长度
    WORD ID;            // 标识符
    WORD Flag_Segment;  // 标识和分段偏移
    BYTE TTL;           // 存活时间
    BYTE Protocol;      // 协议类型
    WORD Checksum;      // 首部校验和
    ULONG SrcIP;        // 源IP地址
    ULONG DstIP;        // 目的IP地址
} IPHeader_t;

typedef struct Data_t {
    FrameHeader_t FrameHeader;
    IPHeader_t IPHeader;
} Data_t;

#pragma pack()

// IP头部校验和计算函数
unsigned short CalculateChecksum(unsigned short* buffer, int size) {
    unsigned long checksum = 0;

    // 将每两个字节相加
    while (size > 1) {
        checksum += *buffer++;
        size -= sizeof(unsigned short);
    }

    // 如果是奇数字节，补最后一个字节
    if (size) {
        checksum += *(unsigned char*)buffer;
    }

    // 将溢出的高位加到低位，直到没有溢出
    while (checksum >> 16) {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }

    // 返回校验和的反码
    return (unsigned short)(~checksum);
}

int main() {
    Data_t* IPPacket;               // 数据包

    pcap_if_t* alldevs;             // 所有设备
    pcap_if_t* d;                   // 选择的设备
    int inum;                       // 设备总数
    int i = 0;
    pcap_t* adhandle;
    struct pcap_pkthdr* header;     // 数据包头部信息
    const u_char* pkt_data;         // 数据包
    char errbuf[PCAP_ERRBUF_SIZE];  // 错误缓冲区

    // 查找所有设备
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        cout << RED << "Error in finding devices: " << errbuf << RESET << endl;
        return 0;
    }
    cout << GREEN << "本机网卡列表为: " << RESET << endl;
    // 列出所有设备
    for (d = alldevs; d; d = d->next)
    {
        cout << BOLD << ++i << ". " << d->name << RESET << endl;
        if (d->description)
            cout << YELLOW << d->description << RESET << endl;
    }

    cout << BOLD << CYAN << "选择设备：" << RESET;
    cin >> inum;
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    // 打开选定的设备
    //IP数据包长度为65535
    adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000,NULL, errbuf);

    pcap_freealldevs(alldevs);

    int res;
    while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
    {
        if (res == 0) {
            continue; // 超时，没有捕获到数据包
        }

        IPPacket = (Data_t*)pkt_data;

        // 解析 MAC 地址
        BYTE* desMac = IPPacket->FrameHeader.DesMAC;
        BYTE* srcMac = IPPacket->FrameHeader.SrcMAC;

        // 使用 stringstream 格式化输出
        stringstream ss;
        ss << hex << setfill('0');

        // 添加时间戳
        auto time_now = chrono::system_clock::to_time_t(chrono::system_clock::now());
        cout << GREEN << "-------------------------------------------" << RESET << endl;
        tm localTime;
        localtime_s(&localTime, &time_now);  // 使用 localtime_s 替代 localtime
        cout << BOLD << "Time: " << RESET << put_time(&localTime, "%Y-%m-%d %X") << endl;

        ss  << setw(2) << (int)desMac[0] << ":"
            << setw(2) << (int)desMac[1] << ":"
            << setw(2) << (int)desMac[2] << ":"
            << setw(2) << (int)desMac[3] << ":"
            << setw(2) << (int)desMac[4] << ":"
            << setw(2) << (int)desMac[5];
        string DesMAC = ss.str();

        ss.str("");  // 清空字符串流
        ss.clear();  // 重置流状态

        ss << setw(2) << (int)srcMac[0] << ":"
            << setw(2) << (int)srcMac[1] << ":"
            << setw(2) << (int)srcMac[2] << ":"
            << setw(2) << (int)srcMac[3] << ":"
            << setw(2) << (int)srcMac[4] << ":"
            << setw(2) << (int)srcMac[5];
        string SrcMAC = ss.str();

        // 输出数据包信息
        cout << BOLD << CYAN << "Source MAC: " << RESET << SrcMAC << endl;
        cout << BOLD << CYAN << "Destination MAC: " << RESET << DesMAC << endl;
        cout << BOLD << "Type: 0x" << hex << ntohs(IPPacket->FrameHeader.FrameType) << RESET
            << "\tLength: " << dec << ntohs(IPPacket->IPHeader.TotalLen) << endl;

        // 计算并验证IP头部校验和
        unsigned short originalChecksum = ntohs(IPPacket->IPHeader.Checksum);
        IPPacket->IPHeader.Checksum = 0;  // 将校验和字段置为0以重新计算

        // 从 Ver_HLen 提取 IP 头部长度（前4位是版本号，后4位是头部长度单位为4字节）
        int ipHeaderLen = (IPPacket->IPHeader.Ver_HLen & 0x0F) * 4;

        // 重新计算校验和
        unsigned short calculatedChecksum = ntohs(CalculateChecksum((unsigned short*)&IPPacket->IPHeader, ipHeaderLen));

        cout << BOLD << "Original Checksum: " << RESET << "0x" << hex << originalChecksum << endl;
        cout << BOLD << "Calculated Checksum: " << RESET << "0x" << hex << calculatedChecksum << endl;

        if (originalChecksum == calculatedChecksum) {
            cout << GREEN << BOLD << "IP header checksum is valid." << RESET << endl;
        }
        else {
            cout << RED << BOLD << "IP header checksum is invalid." << RESET << endl;
        }

        cout << GREEN << "-------------------------------------------" << RESET << endl;
    }

    pcap_close(adhandle);
}
