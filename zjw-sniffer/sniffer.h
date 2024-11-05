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
//���ݽṹ
//MyFrame
class MyFrame : public wxFrame {

public:
    MyFrame(const wxString& title);
    //�ص�����
    void OnStartButtonClicked(wxCommandEvent& event);
    void OnStopButtonClicked(wxCommandEvent& event);
    void AppendText(struct packdisp);
    void FileSave(wxCommandEvent& event);
    void FileOpen(wxCommandEvent& event);
    void  OnGridSelect(wxGridEvent& event);
    void OnFilterChoice(wxCommandEvent& event);
    //�������ο�
    wxTreeCtrl* GetPacketAnalyze() { return PacketAnalyse; }
    //������ʾ��
    wxGrid* Getpacketdisplay() { return packetdisplay; }
    //���grd
    void ClearPacketData();
    //�߳���
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
    //ui�ؼ�
    wxMenuBar* menuBar = new wxMenuBar; //�˵���
    wxChoice* choice;       //����ѡ�������豸
    wxTextCtrl* PacketFilter;  //BPF�����������
    wxButton* startButton;  //��ʼ����
    wxButton* stopButton;   //ֹͣ����
    wxGrid* packetdisplay; //��ʾ���ݰ�������Ϣ
    wxTreeCtrl* PacketAnalyse; //���ݰ��������
    wxTextCtrl* PacketBinary; // ��ʾ���������ݵ��ı���
    wxChoice* filterChoice;  //ɸѡ��ʾ�İ�

    //pcap����
    struct dev* device;   //������������
    pcap_t* handle;        //�򿪵��������
    int no;              //��ȡ�����ݰ�����
    struct packetdump* pktdmp; //���浱ǰ����ʱ��ȡ�����ݰ�
    char errbuf[PCAP_ERRBUF_SIZE];
    int fileexist;
    // �߳����
    wxThread* pcapThread;
    bool isRunning;
};
//�洢ϵͳ���е�����
struct dev {
	const char* name;
	const char* description;
	int number;
	struct dev* next;
};
//��ʾ���ݰ���ʽ
struct packdisp {
    int no;                             // ���
    std::string time;                  // ���ݰ�����ʱ��
    int length;                        // ���ݰ�����
    char protocol[40];                 // ���ݰ�Э������
    char srcIP[INET_ADDRSTRLEN];   // Դ IP ��ַ
    char srcMAC[18];                // Դ MAC ��ַ
    char destIP[INET_ADDRSTRLEN]; // Ŀ�� IP ��ַ
    char destMAC[18];           // Ŀ�� MAC ��ַ
    int srcport;
    int dstport;
};
//�������ݰ���ʽ
struct packetdump {
    const struct pcap_pkthdr *header;
    const u_char* pkt_data;
    packetdump* next;
};

// ���� IP ͷ�ṹ
struct iphdr {
    unsigned char  ip_hl : 4;      // ͷ������
    unsigned char  ip_v : 4;       // IP �汾
    unsigned char  ip_tos;       // ��������
    unsigned short ip_tot_len;   // �ܳ���
    unsigned short ip_id;        // ��ʶ��
    unsigned short ip_off;       // Ƭƫ��
    unsigned char  ip_ttl;       // ����ʱ��
    unsigned char  ip_protocol;   // Э��
    unsigned short ip_check;     // У���
    struct in_addr ip_saddr;     // Դ IP ��ַ
    struct in_addr ip_daddr;     // Ŀ�� IP ��ַ
};
// ������̫��ͷ���ṹ��
struct ether_header {
    uint8_t ether_dhost[6];  // Ŀ�� MAC ��ַ
    uint8_t ether_shost[6];  // Դ MAC ��ַ
    uint16_t ether_type;      // ��̫������
};
//����tcpͷ���ṹ��
struct tcp_header {
    uint16_t th_sport; // Դ�˿�
    uint16_t th_dport; // Ŀ�Ķ˿�
    uint32_t th_seq;   // ���к�
    uint32_t th_ack;   // ȷ�Ϻ�
    unsigned char th_offx2; // ͷ���Ⱥͱ���λ
    unsigned char th_flags;   // ��־λ
    uint16_t th_win;   // ���ڴ�С
    uint16_t th_sum;   // У���
    uint16_t th_urp;   // ����ָ��
};
//����udpͷ���ṹ��
struct udp_header {
    uint16_t uh_sport; // Դ�˿�
    uint16_t uh_dport; // Ŀ�Ķ˿�
    uint16_t uh_ulen;  // ����
    uint16_t uh_sum;   // У���
};
//IP��Э��hash��
extern std::unordered_map<uint8_t, std::string> ipProtocolMap;
//flag�ֶν���
#define TH_FIN  0x01 // Finish
#define TH_SYN  0x02 // Synchronize
#define TH_RST  0x04 // Reset
#define TH_PUSH 0x08 // Push
#define TH_ACK  0x10 // Acknowledgment
#define TH_URG  0x20 // Urgent


//����
//���������γ��б�
struct dev* finddevnames(void);
//��������̫��ͷ��IPͷ��TCP/UDPͷ
void Packet_Analyse(MyFrame* frame, const struct pcap_pkthdr* header, const u_char* PacketData);
//���ݰ�תΪ����ʾ��ʽ
struct packdisp  Packet_Display(const struct pcap_pkthdr* header, const u_char* pkt_data, int* order);
//���ݰ�����
int Save_Captured_Packets(const char* filePath, struct packetdump *pktdmp, pcap_t* handle);
//�ļ����ݰ���ȡ��������ʾ
struct packetdump* LoadAndDisplayPcapFile(const char* filepath);
//���ݰ�������������ʾ
void Binary_Show(wxString* binaryText, const u_char* data, size_t dataSize);
//����Ӧ�ò�Э��
std::string parse_tcp_data(const u_char* data, int len, uint16_t sourcePort, uint16_t destPort);
std::string parse_udp_data(const u_char* data, int len, uint16_t sourcePort, uint16_t destPort);