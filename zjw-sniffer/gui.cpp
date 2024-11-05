#include "sniffer.h"
class MyApp : public wxApp {
public:
    virtual bool OnInit();
};
IMPLEMENT_APP(MyApp)
// �߳���ʵ��
MyFrame::PcapThread::PcapThread(MyFrame* handler,std::string name)
    : wxThread(wxTHREAD_JOINABLE), handler(handler), devname(name)
{
}
MyFrame::PcapThread::~PcapThread()
{
}
wxThread::ExitCode MyFrame::PcapThread::Entry()
{
    const char* csdevdescrip = devname.c_str();
    struct dev* tmp;
    tmp =handler->device;
    for (; tmp != NULL && strcmp(tmp->description, csdevdescrip); tmp = tmp->next);

    //�������ӿ�
    handler->handle = pcap_open_live(tmp->name,	// name of the device
        65536,			// portion of the packet to capture. 
        // 65536 grants that the whole packet will be captured on all the MACs.
        1,				// promiscuous mode (nonzero means promiscuous)
        1000,			// read timeout
        errbuf			// error buffer
    );
    
    //�ص�����
    auto packetHandler = [](u_char* user, const struct pcap_pkthdr* header, const u_char* pkt_data) {
        MyFrame::PcapThread* thread = reinterpret_cast<MyFrame::PcapThread*>(user);

        //�������ݰ�
        if (!(thread->handler->pktdmp))  //��һ�����ݰ�
        {
            thread->handler->pktdmp = (packetdump*)malloc(sizeof(struct packetdump));
            thread->handler->pktdmp->header = (const struct pcap_pkthdr*)malloc(sizeof(const struct pcap_pkthdr));
            memcpy((void *)(thread->handler->pktdmp->header), header,sizeof(const struct pcap_pkthdr));
            thread->handler->pktdmp->pkt_data = (u_char*)malloc(header->len);
            memcpy((void*)(thread->handler->pktdmp->pkt_data), pkt_data, header->len);
            thread->handler->pktdmp->next = NULL;
        }
        else                            //β�巨
        {
            struct packetdump *ptr = thread->handler->pktdmp;
            while (ptr->next != NULL)
                ptr = ptr->next;
            struct packetdump* tmp;
            tmp= (packetdump*)malloc(sizeof(struct packetdump));
            tmp->header = (const struct pcap_pkthdr*)malloc(sizeof(const struct pcap_pkthdr));
            memcpy((void*)(tmp->header), header, sizeof(const struct pcap_pkthdr));
            tmp->pkt_data = (u_char*)malloc(header->len);
            memcpy((void*)(tmp->pkt_data), pkt_data, header->len);
            tmp->next = NULL;
            ptr->next = tmp;
        }
        //�������ݰ�
        struct packdisp  packet;
        packet = Packet_Display(header, pkt_data, &(thread->handler->no));
        
        
        

        //�̴߳�����Ϣ�������̸���gui
        wxTheApp->CallAfter([thread, packet]() {
            thread->handler->AppendText(packet);
            });
        };
    
    //��ȡ����������
    wxString FilterCondition = handler->PacketFilter->GetValue();
    if (!FilterCondition.IsEmpty()) {
        struct bpf_program fp;
        if (pcap_compile(handler->handle, &fp, FilterCondition.mb_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            wxMessageBox("������������ʧ�ܣ�", "����", wxOK | wxICON_ERROR);
            handler->PacketFilter->Enable();  // ��������ʱ�ָ���ť״̬
            handler->startButton->Enable(true);
            handler->stopButton->Enable(false);
            handler->choice->Enable();
            pcap_close(handler->handle);
            return (wxThread::ExitCode)1;
        }

        if (pcap_setfilter(handler->handle, &fp) == -1) {
            wxMessageBox("�޷����ù�������", "����", wxOK | wxICON_ERROR);
            handler->PacketFilter->Enable();  // ��������ʱ�ָ���ť״̬
            handler->startButton->Enable(true);
            handler->stopButton->Enable(false);
            handler->choice->Enable();
            pcap_close(handler->handle);
            return (wxThread::ExitCode)1;
        }
        pcap_freecode(&fp);
    }

    //��������
    pcap_loop(handler->handle, 0, packetHandler, reinterpret_cast<u_char*>(this));
    wxMessageBox("������ֹͣ", "��ʾ", wxICON_INFORMATION);
    handler->isRunning = false;
    return (wxThread::ExitCode)0;
}

bool MyApp::OnInit() {
    MyFrame* frame = new MyFrame("zjw-sniffer");
    frame->Show(true);
    return true;
}
//Myframeʵ��
MyFrame::MyFrame(const wxString& title)
    : wxFrame(nullptr, wxID_ANY, title,wxDefaultPosition, wxSize(1200, 800)),
    pcapThread(nullptr),
    isRunning(false)
{
    wxPanel* panel = new wxPanel(this, wxID_ANY);

    // ���������ò˵�
    wxMenuBar* menuBar = new wxMenuBar();
    wxMenu* fileMenu = new wxMenu;
    fileMenu->Append(wxID_SAVE, "&����\tCtrl-S", "��������������ݰ�");
    fileMenu->Append(wxID_OPEN, "&��\tCtrl-O", "�����ݰ��ļ�");
    menuBar->Append(fileMenu, "&�ļ�");
    SetMenuBar(menuBar);

    // ��ʼ������ѡ��������
    choice = new wxChoice(panel, wxID_ANY, wxDefaultPosition, wxSize(200, -1));
    choice->Append("-----��ѡ�������豸----");  // �����ʾ��

    // ��ʼ������
    no = 1;
    pktdmp = NULL;
    fileexist = 1;

    // ��������б�
    struct dev* scandev;
    device = finddevnames();
    scandev = device;
    for (; scandev; scandev = scandev->next) {
        choice->Append(scandev->description);
    }
    choice->SetSelection(0);  // Ĭ��ѡ����ʾ��

    // �����������������
    PacketFilter = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition, wxSize(200, -1));
    PacketFilter->SetHint("�������������");

    // ������ť
    startButton = new wxButton(panel, wxID_ANY, "��ʼ����", wxDefaultPosition, wxSize(100, -1));
    stopButton = new wxButton(panel, wxID_ANY, "ֹͣ����", wxDefaultPosition, wxSize(100, -1));
    stopButton->Enable(false);  // ��ʼ����״̬


    // ��������ؼ�
    packetdisplay = new wxGrid(panel, wxID_ANY, wxDefaultPosition);
    packetdisplay->CreateGrid(0, 8);  // ��ʼ����Ϊ0������Ϊ8
    packetdisplay->SetColLabelValue(0, "���");
    packetdisplay->SetColLabelValue(1, "ʱ��");
    packetdisplay->SetColLabelValue(2, "������");
    packetdisplay->SetColLabelValue(3, "Э��");
    packetdisplay->SetColLabelValue(4, "ԴMAC��ַ");
    packetdisplay->SetColLabelValue(5, "Ŀ��MAC��ַ");
    packetdisplay->SetColLabelValue(6, "ԴIP��ַ");
    packetdisplay->SetColLabelValue(7, "Ŀ��IP��ַ");
    packetdisplay->SetColSize(0, 80);
    packetdisplay->SetColSize(1, 150);
    packetdisplay->SetColSize(2, 80);
    packetdisplay->SetColSize(3, 150);
    packetdisplay->SetColSize(4, 180);
    packetdisplay->SetColSize(5, 180);
    packetdisplay->SetColSize(6, 150);
    packetdisplay->SetColSize(7, 150);
    packetdisplay->SetSize(packetdisplay->GetBestSize());
    packetdisplay->EnableGridLines(true);
    packetdisplay->SetRowLabelSize(0);
    packetdisplay->SetGridLineColour(*wxLIGHT_GREY);
    packetdisplay->EnableEditing(false);
    packetdisplay->SetDefaultCellAlignment(wxALIGN_CENTER, wxALIGN_CENTER);

    //������ʾɸѡ��
    filterChoice = new wxChoice(panel, wxID_ANY, wxDefaultPosition, wxSize(200, -1));
    filterChoice->Append("-----ȫ��----");
    filterChoice->Append("IPv4");
    filterChoice->Append("IPv6");
    filterChoice->Append("TCP");
    filterChoice->Append("UDP");
    filterChoice->Append("HTTP");
    filterChoice->SetSelection(0);
    // �������η�����
    PacketAnalyse = new wxTreeCtrl(panel, wxID_ANY, wxDefaultPosition, wxSize(400, 200), wxTR_DEFAULT_STYLE | wxTR_HIDE_ROOT);
    wxTreeItemId root = PacketAnalyse->AddRoot("������Ϣ");
    wxTreeItemId child = PacketAnalyse->AppendItem(root, "ʾ��������Ϣ"); // ���ʾ���ӽڵ�

    // ������ʾ���������ݵ��ı���
    PacketBinary = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition, wxSize(600, 200), wxTE_MULTILINE | wxTE_READONLY);
    PacketBinary->SetFont(wxFont(10, wxFONTFAMILY_TELETYPE, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL)); // ����Ϊ�ȿ�����


    // ʹ�� sizer ����
    wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);      // ����ֱ����
    wxBoxSizer* topSizer = new wxBoxSizer(wxHORIZONTAL);     // ����ˮƽ���֣���������ѡ�񡢹��˿򡢰�ť

    // ������ѡ�񡢹��˿򡢰�ť��ӵ�ͬһ��
    topSizer->Add(new wxStaticText(panel, wxID_ANY, "�����豸��"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    topSizer->Add(choice, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, 10);
    topSizer->Add(new wxStaticText(panel, wxID_ANY, "BPF��������"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    topSizer->Add(PacketFilter, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, 10);
    topSizer->Add(new wxStaticText(panel, wxID_ANY, "���ݰ�ɸѡ��"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    topSizer->Add(filterChoice, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, 10);
    topSizer->Add(startButton, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    topSizer->Add(stopButton, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);

    // ����һ��ˮƽ sizer �������οؼ��Ͷ�����������ʾ��
    wxBoxSizer* bottomSizer = new wxBoxSizer(wxHORIZONTAL);
    bottomSizer->Add(PacketAnalyse, 1, wxALL | wxEXPAND | wxCENTER, 10);   // ��� PacketAnalyse �ؼ�
    bottomSizer->Add(PacketBinary, 1, wxALL | wxEXPAND | wxCENTER, 10);     // ��� paketBinary �ؼ�

    // ���ؼ���ӵ���������
    mainSizer->Add(topSizer, 0, wxALL | wxEXPAND, 10);
    mainSizer->Add(packetdisplay, 1, wxALL | wxEXPAND | wxCENTER, 20);  // ����ؼ�
    mainSizer->Add(bottomSizer, 1, wxALL | wxEXPAND | wxCENTER, 10); // ��ӵײ��������ı���

    panel->SetSizerAndFit(mainSizer);  // ����panel��sizer���Զ������ߴ�

    // ���¼�
    startButton->Bind(wxEVT_BUTTON, &MyFrame::OnStartButtonClicked, this);
    stopButton->Bind(wxEVT_BUTTON, &MyFrame::OnStopButtonClicked, this);
    filterChoice->Bind(wxEVT_CHOICE, &MyFrame::OnFilterChoice, this);
    Bind(wxEVT_MENU, &MyFrame::FileSave, this, wxID_SAVE);
    Bind(wxEVT_MENU, &MyFrame::FileOpen, this,wxID_OPEN);
    packetdisplay->Bind(wxEVT_GRID_SELECT_CELL, &MyFrame::OnGridSelect, this);
 
}
//���ȷ�����������豸����ʼ����
void MyFrame::OnStartButtonClicked(wxCommandEvent& event) {
    //�ر���һ��handle
    if(!handle)
        pcap_close(handle);
    //����ȷ��ѡ����һ����Ч�������豸
    if (!isRunning)
    {
        // ��ȡѡ�е�����ӿ�
        int selection = choice->GetSelection();
        if (selection == 0)
        {
            wxMessageBox("��ѡ��һ����Ч����ӿ�", "����", wxICON_WARNING);
            return;
        }
        //��ȡ�豸
        wxString selectedDev = choice->GetString(selection);
        std::string devicename = std::string(selectedDev.mb_str());
        // ��� pktdmp �Ƿ�Ϊ��
        if (pktdmp != nullptr && fileexist==0) {
            // �����Ի���ѯ���û��Ƿ񱣴����ݰ�
            int response = wxMessageBox("��ǰ�����Ѳ�������ݰ����Ƿ񱣴�?", "��ʾ", wxYES_NO | wxCANCEL | wxICON_QUESTION);
            if (response == wxYES) {
                // ���ñ������ݰ�����
                FileSave(event);
                // ��� pktdmp �� grid
                ClearPacketData();
            }
            else if (response == wxNO) {
                // ��� pktdmp �� grid
                ClearPacketData();
            }
            else {
                return; // �û�ѡ��ȡ�����˳�
            }
        }
        else if(pktdmp != nullptr)
            // ��� pktdmp �� grid
            ClearPacketData();
        // ������̨�߳�
        pcapThread = new PcapThread(this, devicename );
        if (pcapThread->Run() != wxTHREAD_NO_ERROR)
        {
            wxMessageBox("�޷����������߳�", "����", wxICON_ERROR);
            delete pcapThread;
            pcapThread = nullptr;
            return;
        }
        isRunning = true;
        fileexist = 0;
        // ���ÿ�ʼ��ť������ֹͣ��ť,���������򣬽��ù��������
        startButton->Enable(false);
        stopButton->Enable(true);
        choice->Disable();  
        PacketFilter->Disable();
    }
}

//���ֹͣ��ָ�״̬
void MyFrame::OnStopButtonClicked(wxCommandEvent& event) {
   
    if (isRunning) {
        // ֹͣ�߳�
        if (pcapThread) {
            pcap_breakloop(handle); // �ж� pcap_loop
        }
        isRunning = false;
    }
        //�ָ���ť״̬
        startButton->Enable(true);
        stopButton->Enable(false);
        choice->Enable();  
        PacketFilter->Enable();
    
}

//��������ʾ�����һ�����ݰ���Ϣ
void MyFrame::AppendText(struct packdisp package)
{
   
    int row = packetdisplay->GetNumberRows();
    packetdisplay->AppendRows(1);  // �������

    // ���ṹ���ֶ�ת��Ϊ wxString ����䵽������
    packetdisplay->SetCellValue(row, 0, wxString::Format("%d", package.no));
    packetdisplay->SetCellValue(row, 1, wxString::Format("%s", package.time.c_str()));
    packetdisplay->SetCellValue(row, 2, wxString::Format("%d", package.length));
    packetdisplay->SetCellValue(row, 3, wxString::Format("%s", package.protocol));
    packetdisplay->SetCellValue(row, 4, wxString::Format("%s", package.srcMAC));
    packetdisplay->SetCellValue(row, 5, wxString::Format("%s", package.destMAC));
    packetdisplay->SetCellValue(row, 6, wxString::Format("%s", package.srcIP));
    packetdisplay->SetCellValue(row, 7, wxString::Format("%s", package.destIP));
    

}

//���ݰ�����
void MyFrame::FileSave(wxCommandEvent& event) {
    if (fileexist == 1)
    {
        wxMessageBox("û����Ҫ������ļ�", "��ʾ", wxICON_INFORMATION);
        return;
    }
    // �����ļ�����Ի���
    wxFileDialog saveFileDialog(this, _("�������ݰ�"), "", "",
        "PCAP files (*.pcap)|*.pcap", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);

    if (saveFileDialog.ShowModal() == wxID_CANCEL) {
        return; // �û�ȡ��
    }

    // ��ȡ�ļ�·��
    wxString filePath = saveFileDialog.GetPath();
    fileexist = 1;
    // �������ݰ����溯��
    if(!Save_Captured_Packets(filePath.ToStdString().c_str(),pktdmp, handle))
        wxMessageBox("����ʧ��", "����", wxICON_WARNING);
    else
        wxMessageBox("����ɹ�", "��ʾ", wxICON_INFORMATION);
}

//���ݰ���
void MyFrame::FileOpen(wxCommandEvent& event)
{
    // ��� pktdmp �Ƿ�Ϊ��
    if (pktdmp != nullptr && fileexist == 0) {
        // �����Ի���ѯ���û��Ƿ񱣴����ݰ�
        int response = wxMessageBox("��ǰ�����Ѳ�������ݰ����Ƿ񱣴�?", "��ʾ", wxYES_NO | wxCANCEL | wxICON_QUESTION);
        if (response == wxYES) {
            // ���ñ������ݰ�����
            FileSave(event);
            // ��� pktdmp �� grid
            ClearPacketData();
        }
        else if (response == wxNO) {
            // ��� pktdmp �� grid
            ClearPacketData();
        }
        else {
            return; // �û�ѡ��ȡ�����˳�
        }
    }
    else if (pktdmp != nullptr)
        // ��� pktdmp �� grid
        ClearPacketData();
    // �����ļ��򿪶Ի���
    wxFileDialog openFileDialog(this, _("ѡ��һ��PCAP�ļ�"), "", "",
        "PCAP files (*.pcap)|*.pcap", wxFD_OPEN | wxFD_FILE_MUST_EXIST);

    if (openFileDialog.ShowModal() == wxID_CANCEL) {
        return; // �û�ȡ��
    }

    // ��ȡ�ļ�·��
    wxString filePath = openFileDialog.GetPath();
    // ����PCAP�ļ�����ʾ��wxGrid��
    pktdmp = LoadAndDisplayPcapFile(filePath.c_str());
    if (pktdmp==NULL) {
        wxMessageBox("�޷��򿪻�����ļ�", "����", wxICON_ERROR);
    }
    //�������ݰ�
    struct packdisp  packet;
    struct packetdump* ptr = pktdmp;
    while (ptr != NULL)
    {
        packet = Packet_Display(ptr->header, ptr->pkt_data, &no);
        AppendText(packet);
        ptr = ptr->next;
    }
    fileexist = 1;
}

//��������ɸѡˢ����ʾ
void MyFrame::OnFilterChoice(wxCommandEvent& event) {
    wxString selected = event.GetString();
    
    // ���������У����ݹ���������ʾ��������
    for (int row = 0; row < packetdisplay->GetNumberRows(); ++row) {
        wxString protocol = packetdisplay->GetCellValue(row, 3);
        bool showRow = (selected == "-----ȫ��----") || (protocol.Find(selected) != wxNOT_FOUND);
        
        // ����������ʾ�������� 
        if (showRow) {
            packetdisplay->ShowRow(row);
        }
        else {
            packetdisplay->HideRow(row);
        }
    }

    packetdisplay->Refresh(); // ˢ����ʾ
}

//���η�����������ƿ���ʾ��ϸ������Ϣ
void  MyFrame::OnGridSelect(wxGridEvent& event)
{
    int selectedRow = event.GetRow();
    if (selectedRow < 0)
        return;
    //��ȡ��ǰ���ݰ�
    packetdump* currentPacket = pktdmp; 
    int i;
    for (i = 0; i < selectedRow && currentPacket != nullptr; ++i) {
        currentPacket = currentPacket->next;
    }

    if (currentPacket != nullptr) {
        // ��� wxTreeCtrl
        PacketAnalyse->DeleteAllItems();

        // ������η�����Ϣ
        wxTreeItemId root = PacketAnalyse->AddRoot("Packet Details");

        // ��ȡ���ݰ�����
        const u_char* PacketData = currentPacket->pkt_data; // ���ݰ�����
        size_t dataSize = currentPacket->header->len; // ���ݰ�����
        const struct pcap_pkthdr* header = currentPacket->header;//��̫��ͷ��
        Packet_Analyse(this, header, PacketData);

        // ��ʽ������������
        wxString binaryText;
        Binary_Show(&binaryText, PacketData, dataSize);
        PacketBinary->SetValue(binaryText);
    }
}

//��ձ�������ݰ�����ʾ��
void MyFrame::ClearPacketData() {
    // ������ݰ�����
    while (pktdmp != nullptr) {
        packetdump* temp = pktdmp;
        pktdmp = pktdmp->next;
        free(temp);
    }

    // ��� wxGrid ����
    int rowCount = packetdisplay->GetNumberRows();
    if (rowCount > 0) {
        packetdisplay->DeleteRows(0, rowCount); // ɾ��������
    }
    //���������ʾ���Ͷ������ı���ʾ��
    PacketAnalyse->DeleteAllItems();
    PacketBinary->Clear();

    //��Ź���
    no = 1;
}