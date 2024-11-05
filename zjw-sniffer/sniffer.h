#include <winsock2.h>
#include <ws2tcpip.h>
#include <wx/treebase.h>
#include <wx/treectrl.h>
#include <wx/string.h>
#include <unordered_map> 
#include <string> 
#include <pcap.h>
#include <wx/wx.h>
#include <stdio.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <ctime>
#include <iomanip>
#include <cstring>
#include <wx/treebase.h>
#include <wx/treectrl.h>
#include <tchar.h>
#include<wx/grid.h>
#include <cstdint>
//数据结构
//MyFrame
class MyFrame : public wxFrame {

public:
    MyFrame(const wxString& title);
    //回调函数
    void OnStartButtonClicked(wxCommandEvent& event);
    void OnStopButtonClicked(wxCommandEvent& event);
    void AppendText(struct packdisp);
    void FileSave(wxCommandEvent& event);
    void FileOpen(wxCommandEvent& event);
    void  OnGridSelect(wxGridEvent& event);
    void OnFilterChoice(wxCommandEvent& event);
    //返回树形框
    wxTreeCtrl* GetPacketAnalyze() { return PacketAnalyse; }
    //返回显示栏
    wxGrid* Getpacketdisplay() { return packetdisplay; }
    //清空grd
    void ClearPacketData();
    //线程类
    class PcapThread : public wxThread
    {
    public:
        PcapThread(MyFrame* handler, std::string name);
        virtual ~PcapThread();
        MyFrame* handler;
        std::string devname;

    protected:
        virtual ExitCode Entry() override;

    private:
        char errbuf[PCAP_ERRBUF_SIZE];
    };

private:
    //ui控件
    wxMenuBar* menuBar = new wxMenuBar; //菜单栏
    wxChoice* choice;       //下拉选择网卡设备
    wxTextCtrl* PacketFilter;  //BPF过滤器输入框
    wxButton* startButton;  //开始监听
    wxButton* stopButton;   //停止监听
    wxGrid* packetdisplay; //显示数据包基本信息
    wxTreeCtrl* PacketAnalyse; //数据包具体分析
    wxTextCtrl* PacketBinary; // 显示二进制数据的文本框
    wxChoice* filterChoice;  //筛选显示的包

    //pcap数据
    struct dev* device;   //保存网卡数据
    pcap_t* handle;        //打开的网卡句柄
    int no;              //获取的数据包个数
    struct packetdump* pktdmp; //保存当前监听时获取的数据包
    char errbuf[PCAP_ERRBUF_SIZE];
    int fileexist;
    // 线程相关
    wxThread* pcapThread;
    bool isRunning;
};
//存储系统所有的网卡
struct dev {
	const char* name;
	const char* description;
	int number;
	struct dev* next;
};
//显示数据包格式
struct packdisp {
    int no;                             // 序号
    std::string time;                  // 数据包捕获时间
    int length;                        // 数据包长度
    char protocol[40];                 // 数据包协议类型
    char srcIP[INET_ADDRSTRLEN];   // 源 IP 地址
    char srcMAC[18];                // 源 MAC 地址
    char destIP[INET_ADDRSTRLEN]; // 目的 IP 地址
    char destMAC[18];           // 目的 MAC 地址
    int srcport;
    int dstport;
};
//保存数据包格式
struct packetdump {
    const struct pcap_pkthdr *header;
    const u_char* pkt_data;
    packetdump* next;
};

// 定义 IP 头结构
struct iphdr {
    unsigned char  ip_hl : 4;      // 头部长度
    unsigned char  ip_v : 4;       // IP 版本
    unsigned char  ip_tos;       // 服务类型
    unsigned short ip_tot_len;   // 总长度
    unsigned short ip_id;        // 标识符
    unsigned short ip_off;       // 片偏移
    unsigned char  ip_ttl;       // 生存时间
    unsigned char  ip_protocol;   // 协议
    unsigned short ip_check;     // 校验和
    struct in_addr ip_saddr;     // 源 IP 地址
    struct in_addr ip_daddr;     // 目的 IP 地址
};
// 定义以太网头部结构体
struct ether_header {
    uint8_t ether_dhost[6];  // 目的 MAC 地址
    uint8_t ether_shost[6];  // 源 MAC 地址
    uint16_t ether_type;      // 以太网类型
};
//定义tcp头部结构体
struct tcp_header {
    uint16_t th_sport; // 源端口
    uint16_t th_dport; // 目的端口
    uint32_t th_seq;   // 序列号
    uint32_t th_ack;   // 确认号
    unsigned char th_offx2; // 头长度和保留位
    unsigned char th_flags;   // 标志位
    uint16_t th_win;   // 窗口大小
    uint16_t th_sum;   // 校验和
    uint16_t th_urp;   // 紧急指针
};
//定义udp头部结构体
struct udp_header {
    uint16_t uh_sport; // 源端口
    uint16_t uh_dport; // 目的端口
    uint16_t uh_ulen;  // 长度
    uint16_t uh_sum;   // 校验和
};
//IP层协议hash表
extern std::unordered_map<uint8_t, std::string> ipProtocolMap;
//flag字段解析
#define TH_FIN  0x01 // Finish
#define TH_SYN  0x02 // Synchronize
#define TH_RST  0x04 // Reset
#define TH_PUSH 0x08 // Push
#define TH_ACK  0x10 // Acknowledgment
#define TH_URG  0x20 // Urgent


//函数
//查找网卡形成列表
struct dev* finddevnames(void);
//逐层分析以太网头、IP头和TCP/UDP头
void Packet_Analyse(MyFrame* frame, const struct pcap_pkthdr* header, const u_char* PacketData);
//数据包转为可显示形式
struct packdisp  Packet_Display(const struct pcap_pkthdr* header, const u_char* pkt_data, int* order);
//数据包保存
int Save_Captured_Packets(const char* filePath, struct packetdump *pktdmp, pcap_t* handle);
//文件数据包读取并处理显示
struct packetdump* LoadAndDisplayPcapFile(const char* filepath);
//数据包二进制数据显示
void Binary_Show(wxString* binaryText, const u_char* data, size_t dataSize);
//分析应用层协议
std::string parse_tcp_data(const u_char* data, int len, uint16_t sourcePort, uint16_t destPort);
std::string parse_udp_data(const u_char* data, int len, uint16_t sourcePort, uint16_t destPort);