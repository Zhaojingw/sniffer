#include "sniffer.h"
//ip层协议hash表
std::unordered_map<uint8_t, std::string> ipProtocolMap = {
	{0, "Reserved "},
	{1, "ICMP "},
	{2, "IGMP "},
	{3, "GGP "},
	{4, "IPv4 Encapsulation "},
	{5, "ST "},
	{6, "TCP "},
	{7, "CBT "},
	{8, "EGP "},
	{9, "IGP "},
	{10, "BBN RCC "},
	{11, "PUP "},
	{12, "ARGUS "},
	{13, "EMCON "},
	{14, "XNET "},
	{15, "CHAOS "},
	{16, "User Defined 1 "},
	{17, "UDP "},
	{18, "MUX "},
	{19, "DCN Measurement Subsystem "},
	{20, "HMP "},
	{21, "PRM "},
	{22, "XTP "},
	{23, "DDP "},
	{24, "IDRP "},
	{25, "TP++ Protocol "},
	{26, "ILMI "},
	{27, "SCTP "},
	{28, "FC "},
	{29, "WESP "},
	{30, "RDP "},
	{31, "Reserved "},
	{32, "Reserved "},
	{33, "SCTP "},
	{41, "IPv6 "},
	{43, "IPv6 Routing Header "},
	{44, "IPv6 Fragment Header "},
	{46, "RSVP "},
	{47, "GRE "},
	{50, "ESP "},
	{51, "AH "},
	{60, "EIGRP "},
	{67, "L2TP "},
	{68, "DCCP "},
	{89, "OSPF "},
	{128, "IPIP "},
	{253, "Experimental / Reserved "},
	{254, "Experimental / Reserved "}
};
#pragma warning(disable:4996) // 禁用特定警告
// 手动定义 ARP 协议类型
#ifndef IPPROTO_ARP
#define IPPROTO_ARP 0x0806  // ARP 协议号
#endif
//查找网卡接口
struct dev * finddevnames(void)
{
	pcap_if_t* d, *alldevs;
	int i=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct dev *device,*head;
	device = NULL;
	head = NULL;

	//读取网卡接口并保存
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		exit(1);
	}
	for (d = alldevs; d; d = d->next,i++)
	{
		if (i == 0)
		{
			device = (struct dev*)malloc(sizeof(struct dev));
			device->name = d->name;
			device->description = d->description;
			device->number = i;
			device->next = NULL;
			head = device;
		}
		else
		{
			struct dev* tmp;
			tmp= (struct dev*)malloc(sizeof(struct dev));
			tmp->name = d->name;
			tmp->description = d->description;
			tmp->number = i;
			tmp->next = NULL;
			head->next = tmp;
			head = head->next;			
		}
	}
	return device;
}
// 提取 MAC 地址为字符串
std::string MACToString(const u_char* mac) {
	char macStr[18];
	snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return std::string(macStr);
}
//数据包转为可显示形式
struct packdisp  Packet_Display(const struct pcap_pkthdr* header, const u_char* pkt_data,int *order )
{
	struct packdisp packet;
	//编号
	packet.no = *order;
	*order += 1;
	//长度
	packet.length = header->len;
	// 捕获时间
	std::tm timeinfo; // 用于存储转换后的时间
	std::time_t timestamp = header->ts.tv_sec;
	// 使用 localtime_s 将时间转换为本地时间
	localtime_s(&timeinfo, &timestamp);
	// 使用 std::put_time 格式化时间
	char buffer[20];
	strftime(buffer, sizeof(buffer), "%Y.%m.%d %H:%M:%S", &timeinfo);
	packet.time = buffer; // 将格式化后的时间赋值给 packet.time
	//源mac和目的mac
	const struct ether_header* ethHeader = (const struct ether_header*)(pkt_data);
	memcpy(packet.srcMAC, MACToString(ethHeader->ether_shost).c_str(), 18);
	memcpy(packet.destMAC, MACToString(ethHeader->ether_dhost).c_str(), 18);
	uint16_t etherType = ntohs(ethHeader->ether_type);
	if (etherType == 0x0800) { // IPv4
		strcpy(packet.protocol, "IPv4/");
	}
	else if (etherType == 0x86DD) { // IPv6
		strcpy(packet.protocol, "IPv6/");
	}
	else {
		strcpy(packet.protocol, "OTHER/");
	}
	struct iphdr* ipHeader = (struct iphdr*)(pkt_data + 14);
	// 提取协议类型
	auto it = ipProtocolMap.find(ipHeader->ip_protocol);
	if (it != ipProtocolMap.end()) {
		strcat(packet.protocol, it->second.c_str());
	}
	else {
		strcat(packet.protocol, "OTHER");
	}
	//源ip与目的ip
	inet_ntop(AF_INET, &(ipHeader->ip_saddr), packet.srcIP, sizeof(packet.srcIP));
	inet_ntop(AF_INET, &(ipHeader->ip_daddr), packet.destIP, sizeof(packet.destIP));
	
	// 进一步解析应用层协议
	std::string appProtocol;
	if (ipHeader->ip_protocol == IPPROTO_TCP) {
		struct tcp_header *tcpHeader = (struct tcp_header *)(pkt_data + 14 + sizeof(struct iphdr));
		// 处理TCP数据
		packet.srcport = ntohs(tcpHeader->th_sport);
		packet.dstport = ntohs(tcpHeader->th_dport);
		appProtocol = parse_tcp_data(pkt_data + 14 + sizeof(struct iphdr) + sizeof(struct tcp_header), header->len - (14 + sizeof(struct iphdr) + sizeof(struct tcp_header)), packet.srcport, packet.dstport);

		// 拼接应用层协议名到 packet.protocol
		strcat(packet.protocol, appProtocol.c_str());
	}
	else if (ipHeader->ip_protocol == IPPROTO_UDP) {
		struct udp_header* udpHeader = (struct udp_header*)(pkt_data + 14 + sizeof(struct iphdr));
		// 处理UDP数据
		packet.srcport = ntohs(udpHeader->uh_sport);
		packet.dstport = ntohs(udpHeader->uh_dport);
		appProtocol = parse_udp_data(pkt_data + 14 + sizeof(struct iphdr) + sizeof(struct udp_header), header->len - (14 + sizeof(struct iphdr) + sizeof(struct udp_header)), packet.srcport, packet.dstport);

		// 拼接应用层协议名到 packet.protocol
		strcat(packet.protocol, appProtocol.c_str());
	}

	return packet;

}
//保存捕获的数据包
int Save_Captured_Packets(const char *filePath, struct packetdump* pktdmp, pcap_t* handle)
{
	// 打开保存文件
	pcap_dumper_t * dumper;
	dumper = pcap_dump_open(handle, filePath);
	if (dumper == NULL) {
		fprintf(stderr, "Error opening savefile: %s\n", pcap_geterr(handle));
		return 0;
	}
	//遍历pktdmp进行保存
	struct packetdump* ptr = pktdmp;
	while (ptr!=NULL)
	{
		pcap_dump((u_char*)dumper, ptr->header, ptr->pkt_data);
		ptr = ptr->next;
	}
	pcap_dump_close(dumper);
	return 1;
}
//数据包以太网头部、IP头部、TCP/UDP头部解析
void Packet_Analyse(MyFrame* frame, const struct pcap_pkthdr* header, const u_char* PacketData)
{

	wxTreeCtrl* PacketAnalyze = frame->GetPacketAnalyze();
	PacketAnalyze->DeleteAllItems();
	wxTreeItemId root = PacketAnalyze->AddRoot("Packet Details");

	//解析以太网头部信息
	const struct ether_header* ethHeader = (struct ether_header*)PacketData;
	wxTreeItemId ethNode = PacketAnalyze->AppendItem(root, "Ethernet Header");
	PacketAnalyze->AppendItem(ethNode, wxString::Format("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x",
		ethHeader->ether_shost[0], ethHeader->ether_shost[1], ethHeader->ether_shost[2],
		ethHeader->ether_shost[3], ethHeader->ether_shost[4], ethHeader->ether_shost[5]));
	PacketAnalyze->AppendItem(ethNode, wxString::Format("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x",
		ethHeader->ether_dhost[0], ethHeader->ether_dhost[1], ethHeader->ether_dhost[2],
		ethHeader->ether_dhost[3], ethHeader->ether_dhost[4], ethHeader->ether_dhost[5]));
	//协议字段：
	uint16_t etherType = ntohs(ethHeader->ether_type);
	wxString protocolName;

	switch (etherType) {
	case 0x0800:
		protocolName = "IPv4";
		break;
	case 0x0806:
		protocolName = "ARP";
		break;
	case 0x86DD:
		protocolName = "IPv6";
		break;
	case 0x0801:
		protocolName = "X.75";
		break;
	case 0x0805:
		protocolName = "PUP";
		break;
	case 0x8035:
		protocolName = "RARP";
		break;
	case 0x8847:
		protocolName = "MPLS Unicast";
		break;
	case 0x8848:
		protocolName = "MPLS Multicast";
		break;
	case 0x9000:
		protocolName = "Special Use";
		break;
	default:
		protocolName = "Unknown Protocol";
		break;
	}

	// 将协议名称添加到 PacketAnalyze
	PacketAnalyze->AppendItem(ethNode, wxString::Format("Protocol Type: 0x%04x (%s)", etherType, protocolName));

	// 解析 IP 头
	const struct iphdr* ipHeader = (struct iphdr*)(PacketData + sizeof(struct ether_header));
	wxTreeItemId ipNode = PacketAnalyze->AppendItem(root, "IP Header");
	PacketAnalyze->AppendItem(ipNode, wxString::Format("Version: %d", ipHeader->ip_v));
	PacketAnalyze->AppendItem(ipNode, wxString::Format("Service Type: %d", ipHeader->ip_tos));
	PacketAnalyze->AppendItem(ipNode, wxString::Format("Header Length: %d bytes", ipHeader->ip_hl * 4));
	PacketAnalyze->AppendItem(ipNode, wxString::Format("Total Length: %d bytes", ntohs(ipHeader->ip_tot_len)));
	PacketAnalyze->AppendItem(ipNode, wxString::Format("ID: %d", ntohs(ipHeader->ip_id)));
	PacketAnalyze->AppendItem(ipNode, wxString::Format("Fragment Offset: 0x%04x", ntohs(ipHeader->ip_off)));
	PacketAnalyze->AppendItem(ipNode, wxString::Format("TTL: %d", ipHeader->ip_ttl));
	//协议字段
	auto it = ipProtocolMap.find(ipHeader->ip_protocol);
	if (it != ipProtocolMap.end()) {
		PacketAnalyze->AppendItem(ipNode, wxString::Format("Protocol: %d (%s)", ipHeader->ip_protocol, it->second));
	}
	else {
		PacketAnalyze->AppendItem(ipNode, wxString::Format("Protocol: %d (Unknown Protocol)", ipHeader->ip_protocol));
	}
	PacketAnalyze->AppendItem(ipNode, wxString::Format("Header Checksum: 0x%04x", ntohs(ipHeader->ip_check)));
	PacketAnalyze->AppendItem(ipNode, wxString::Format("Source IP: %s", inet_ntoa(ipHeader->ip_saddr)));
	PacketAnalyze->AppendItem(ipNode, wxString::Format("Destination IP: %s", inet_ntoa(ipHeader->ip_daddr)));

	// 根据协议类型解析传输层（TCP/UDP）
	if (ipHeader->ip_protocol == IPPROTO_TCP) {

		const struct tcp_header* tcpHeader = (struct tcp_header*)(PacketData + sizeof(struct ether_header) + (ipHeader->ip_hl * 4));
		wxTreeItemId tcpNode = PacketAnalyze->AppendItem(root, "TCP Header");
		PacketAnalyze->AppendItem(tcpNode, wxString::Format("Source Port: %d", ntohs(tcpHeader->th_sport)));
		PacketAnalyze->AppendItem(tcpNode, wxString::Format("Destination Port: %d", ntohs(tcpHeader->th_dport)));
		PacketAnalyze->AppendItem(tcpNode, wxString::Format("Sequence Number: %u", ntohl(tcpHeader->th_seq)));
		PacketAnalyze->AppendItem(tcpNode, wxString::Format("Ack Number: %u", ntohl(tcpHeader->th_ack)));
		PacketAnalyze->AppendItem(tcpNode, wxString::Format("Header Length: %d bytes", (tcpHeader->th_offx2 >> 4) * 4));
		wxString flagInfo;

		// 解析每个标志位
		if (tcpHeader->th_flags & TH_URG) {
			flagInfo += "URG ";
		}
		if (tcpHeader->th_flags & TH_ACK) {
			flagInfo += "ACK ";
		}
		if (tcpHeader->th_flags & TH_PUSH) {
			flagInfo += "PSH ";
		}
		if (tcpHeader->th_flags & TH_RST) {
			flagInfo += "RST ";
		}
		if (tcpHeader->th_flags & TH_SYN) {
			flagInfo += "SYN ";
		}
		if (tcpHeader->th_flags & TH_FIN) {
			flagInfo += "FIN ";
		}

		// 如果没有设置任何标志位，显示为 "No Flags"
		if (flagInfo.empty()) {
			flagInfo = "No Flags";
		}
		PacketAnalyze->AppendItem(tcpNode, wxString::Format("Flags: 0x%02x，%s", tcpHeader->th_flags, flagInfo));
		PacketAnalyze->AppendItem(tcpNode, wxString::Format("Window Size: %d", ntohs(tcpHeader->th_win)));
		PacketAnalyze->AppendItem(tcpNode, wxString::Format("Checksum: 0x%04x", ntohs(tcpHeader->th_sum)));
		//根据端口解析应用层协议
		std::string appProtocol = parse_tcp_data(PacketData + sizeof(struct ether_header) + (ipHeader->ip_hl * 4) + ((tcpHeader->th_offx2 >> 4) * 4),
			header->len - (sizeof(struct ether_header) + (ipHeader->ip_hl * 4) + ((tcpHeader->th_offx2 >> 4) * 4)), ntohs(tcpHeader->th_sport), ntohs(tcpHeader->th_dport));
		if (!appProtocol.empty()) {
			wxTreeItemId  applayernode = PacketAnalyze->AppendItem(root, "Application Layer");
			PacketAnalyze->AppendItem(applayernode, wxString::Format("Application Layer Protocol: %s", appProtocol));
		}
	}
	else if (ipHeader->ip_protocol == IPPROTO_UDP) {
		const struct udp_header* udpHeader = (struct udp_header*)(PacketData + sizeof(struct ether_header) + (ipHeader->ip_hl * 4));
		wxTreeItemId udpNode = PacketAnalyze->AppendItem(root, "UDP Header");
		PacketAnalyze->AppendItem(udpNode, wxString::Format("Source Port: %d", ntohs(udpHeader->uh_sport)));
		PacketAnalyze->AppendItem(udpNode, wxString::Format("Destination Port: %d", ntohs(udpHeader->uh_dport)));
		PacketAnalyze->AppendItem(udpNode, wxString::Format("Length: %d bytes", ntohs(udpHeader->uh_ulen)));
		PacketAnalyze->AppendItem(udpNode, wxString::Format("Checksum: 0x%04x", ntohs(udpHeader->uh_sum)));
		//根据端口解析应用层协议
		std::string appProtocol = parse_udp_data(PacketData + sizeof(struct ether_header) + (ipHeader->ip_hl * 4) + sizeof(struct udp_header),
			header->len - (sizeof(struct ether_header) + (ipHeader->ip_hl * 4) + sizeof(struct udp_header)), ntohs(udpHeader->uh_sport), ntohs(udpHeader->uh_dport));
		if (!appProtocol.empty()) {
			wxTreeItemId  applayernode = PacketAnalyze->AppendItem(root, "Application Layer");
			PacketAnalyze->AppendItem(applayernode, wxString::Format("Application Layer Protocol: %s", appProtocol));
		}
	}

}
//数据包二进制显示
void Binary_Show(wxString* binaryText, const u_char* data, size_t dataSize)
{
	wxString charText;

	for (size_t i = 0; i < dataSize; i += 16) {
		// 添加偏移量
		binaryText->Append(wxString::Format("%04x  ", static_cast<unsigned>(i)));

		// 添加16字节数据
		for (size_t j = 0; j < 16; ++j) {
			if (i + j < dataSize) {
				binaryText->Append(wxString::Format("%02x ", data[i + j]));

				// 显示对应的字符，如果不是可打印字符则显示点
				char c = data[i + j];
				if (c >= 32 && c <= 126) { // 可打印字符范围
					charText.Append(c);
				}
				else {
					charText.Append('.');
				}
			}
			else {
				binaryText->Append("   "); // 添加空格以对齐
				charText.Append('.'); // 没有对应字符时显示点
			}
		}
		// 添加字符显示到二进制文本后
		binaryText->Append(" | ").Append(charText).Append("\n");
		charText.Clear(); // 清空字符文本，准备下一行
	}
	// 显示二进制数据
}
//数据包读取、分析与显示
struct packetdump* LoadAndDisplayPcapFile(const char* filepath)
{
	struct packetdump* pktdmp=NULL;
	// 打开PCAP文件
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_offline(filepath, errbuf);
	if (handle == nullptr) {
		return NULL; // 文件打开失败
	}
	struct pcap_pkthdr header;
	const u_char* pkt_data;
	//循环读取全部数据并保存到pkttmp
	 // 循环读取每个数据包
	while ((pkt_data = pcap_next(handle, &header)) != nullptr) {
	
		//保存数据包
		if (!(pktdmp))  //第一个数据包
		{
			pktdmp = (packetdump*)malloc(sizeof(struct packetdump));
			pktdmp->header = (const struct pcap_pkthdr*)malloc(sizeof(const struct pcap_pkthdr));
			memcpy((void*)(pktdmp->header), &header, sizeof(const struct pcap_pkthdr));
			pktdmp->pkt_data = (u_char*)malloc(header.len);
			memcpy((void*)(pktdmp->pkt_data), pkt_data, header.len);
			pktdmp->next = NULL;
		}
		else                            //尾插法
		{
			struct packetdump* ptr = pktdmp;
			while (ptr->next != NULL)
				ptr = ptr->next;
			struct packetdump* tmp;
			tmp = (packetdump*)malloc(sizeof(struct packetdump));
			tmp->header = (const struct pcap_pkthdr*)malloc(sizeof(const struct pcap_pkthdr));
			memcpy((void*)(tmp->header), &header, sizeof(const struct pcap_pkthdr));
			tmp->pkt_data = (u_char*)malloc(header.len);
			memcpy((void*)(tmp->pkt_data), pkt_data, header.len);
			tmp->next = NULL;
			ptr->next = tmp;
		}
	}
	return pktdmp;
}
// 解析TCP应用层数据
std::string parse_tcp_data(const u_char* data, int len, uint16_t sourcePort, uint16_t destPort) {
	if (len <= 0) return "";

	// 将 TCP 数据转换为字符串
	std::string tcp_data(reinterpret_cast<const char*>(data), len);

	// 根据端口检查 HTTP 和 HTTPS
	if (destPort == 80 || sourcePort == 80) {
		return "(HTTP)";
	}
	if (destPort == 443 || sourcePort == 443) {
		// 检查是否为 HTTPS
		if (len > 5 && data[0] == 0x16) { // TLS Handshake Record Type
			return "(HTTPS)";
		}
		return "(HTTP)"; // 可以处理 HTTP/2
	}

	// 检查是否是 FTP
	if ((destPort == 21 || sourcePort == 21) && (tcp_data.find("USER ") == 0 || tcp_data.find("PASS ") == 0)) {
		return "(FTP)";
	}

	// 检查是否是 SMTP
	if ((destPort == 25 || sourcePort == 25) && (tcp_data.find("EHLO ") == 0 ||
		tcp_data.find("MAIL FROM:") == 0 || tcp_data.find("RCPT TO:") == 0 || tcp_data.find("DATA") == 0)) {
		return "(SMTP)";
	}

	// 检查是否是 SSH
	if ((destPort == 22 || sourcePort == 22) && (tcp_data.find("SSH-") == 0)) {
		return "(SSH)";
	}
	if ((destPort == 5060 || sourcePort == 5060) && tcp_data.find("SIP") == 0) {
		return "(SIP)";
	}
	return "";
}
// 解析UDP应用层数据
std::string parse_udp_data(const u_char* data, int len, uint16_t sourcePort, uint16_t destPort) {
	if (len <= 0) return "";

	// 将 UDP 数据转换为字符串
	std::string udp_data(reinterpret_cast<const char*>(data), len);

	// 根据端口检查 DNS
	if (destPort == 53 || sourcePort == 53) {
		return "(DNS)";
	}

	// 根据端口检查 DHCP
	if (destPort == 67 || sourcePort == 67 || destPort == 68 || sourcePort == 68) {
		return "(DHCP)";
	}

	// 根据端口检查 TFTP
	if (destPort == 69 || sourcePort == 69) {
		return "(TFTP)";
	}

	// 根据端口检查 SNMP
	if (destPort == 161 || sourcePort == 161) {
		return "(SNMP)";
	}

	// 根据端口检查 RIP
	if (destPort == 520 || sourcePort == 520) {
		return "(RIP)";
	}

	return "";
}
