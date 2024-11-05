#include "sniffer.h"
class MyApp : public wxApp {
public:
    virtual bool OnInit();
};
IMPLEMENT_APP(MyApp)
// 线程类实现
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

    //打开网卡接口
    handler->handle = pcap_open_live(tmp->name,	// name of the device
        65536,			// portion of the packet to capture. 
        // 65536 grants that the whole packet will be captured on all the MACs.
        1,				// promiscuous mode (nonzero means promiscuous)
        1000,			// read timeout
        errbuf			// error buffer
    );
    
    //回调函数
    auto packetHandler = [](u_char* user, const struct pcap_pkthdr* header, const u_char* pkt_data) {
        MyFrame::PcapThread* thread = reinterpret_cast<MyFrame::PcapThread*>(user);

        //保存数据包
        if (!(thread->handler->pktdmp))  //第一个数据包
        {
            thread->handler->pktdmp = (packetdump*)malloc(sizeof(struct packetdump));
            thread->handler->pktdmp->header = (const struct pcap_pkthdr*)malloc(sizeof(const struct pcap_pkthdr));
            memcpy((void *)(thread->handler->pktdmp->header), header,sizeof(const struct pcap_pkthdr));
            thread->handler->pktdmp->pkt_data = (u_char*)malloc(header->len);
            memcpy((void*)(thread->handler->pktdmp->pkt_data), pkt_data, header->len);
            thread->handler->pktdmp->next = NULL;
        }
        else                            //尾插法
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
        //分析数据包
        struct packdisp  packet;
        packet = Packet_Display(header, pkt_data, &(thread->handler->no));
        
        
        

        //线程传递信息给主进程更新gui
        wxTheApp->CallAfter([thread, packet]() {
            thread->handler->AppendText(packet);
            });
        };
    
    //获取包过滤条件
    wxString FilterCondition = handler->PacketFilter->GetValue();
    if (!FilterCondition.IsEmpty()) {
        struct bpf_program fp;
        if (pcap_compile(handler->handle, &fp, FilterCondition.mb_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            wxMessageBox("过滤条件编译失败！", "错误", wxOK | wxICON_ERROR);
            handler->PacketFilter->Enable();  // 发生错误时恢复按钮状态
            handler->startButton->Enable(true);
            handler->stopButton->Enable(false);
            handler->choice->Enable();
            pcap_close(handler->handle);
            return (wxThread::ExitCode)1;
        }

        if (pcap_setfilter(handler->handle, &fp) == -1) {
            wxMessageBox("无法设置过滤器！", "错误", wxOK | wxICON_ERROR);
            handler->PacketFilter->Enable();  // 发生错误时恢复按钮状态
            handler->startButton->Enable(true);
            handler->stopButton->Enable(false);
            handler->choice->Enable();
            pcap_close(handler->handle);
            return (wxThread::ExitCode)1;
        }
        pcap_freecode(&fp);
    }

    //开启监听
    pcap_loop(handler->handle, 0, packetHandler, reinterpret_cast<u_char*>(this));
    wxMessageBox("监听已停止", "提示", wxICON_INFORMATION);
    handler->isRunning = false;
    return (wxThread::ExitCode)0;
}

bool MyApp::OnInit() {
    MyFrame* frame = new MyFrame("zjw-sniffer");
    frame->Show(true);
    return true;
}
//Myframe实现
MyFrame::MyFrame(const wxString& title)
    : wxFrame(nullptr, wxID_ANY, title,wxDefaultPosition, wxSize(1200, 800)),
    pcapThread(nullptr),
    isRunning(false)
{
    wxPanel* panel = new wxPanel(this, wxID_ANY);

    // 创建并设置菜单
    wxMenuBar* menuBar = new wxMenuBar();
    wxMenu* fileMenu = new wxMenu;
    fileMenu->Append(wxID_SAVE, "&保存\tCtrl-S", "保存监听到的数据包");
    fileMenu->Append(wxID_OPEN, "&打开\tCtrl-O", "打开数据包文件");
    menuBar->Append(fileMenu, "&文件");
    SetMenuBar(menuBar);

    // 初始化网卡选择下拉框
    choice = new wxChoice(panel, wxID_ANY, wxDefaultPosition, wxSize(200, -1));
    choice->Append("-----请选择网卡设备----");  // 添加提示语

    // 初始化数据
    no = 1;
    pktdmp = NULL;
    fileexist = 1;

    // 填充网卡列表
    struct dev* scandev;
    device = finddevnames();
    scandev = device;
    for (; scandev; scandev = scandev->next) {
        choice->Append(scandev->description);
    }
    choice->SetSelection(0);  // 默认选择提示项

    // 创建过滤条件输入框
    PacketFilter = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition, wxSize(200, -1));
    PacketFilter->SetHint("请输入过滤条件");

    // 创建按钮
    startButton = new wxButton(panel, wxID_ANY, "开始监听", wxDefaultPosition, wxSize(100, -1));
    stopButton = new wxButton(panel, wxID_ANY, "停止监听", wxDefaultPosition, wxSize(100, -1));
    stopButton->Enable(false);  // 初始禁用状态


    // 创建网格控件
    packetdisplay = new wxGrid(panel, wxID_ANY, wxDefaultPosition);
    packetdisplay->CreateGrid(0, 8);  // 初始行数为0，列数为8
    packetdisplay->SetColLabelValue(0, "序号");
    packetdisplay->SetColLabelValue(1, "时间");
    packetdisplay->SetColLabelValue(2, "包长度");
    packetdisplay->SetColLabelValue(3, "协议");
    packetdisplay->SetColLabelValue(4, "源MAC地址");
    packetdisplay->SetColLabelValue(5, "目的MAC地址");
    packetdisplay->SetColLabelValue(6, "源IP地址");
    packetdisplay->SetColLabelValue(7, "目的IP地址");
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

    //创建显示筛选框
    filterChoice = new wxChoice(panel, wxID_ANY, wxDefaultPosition, wxSize(200, -1));
    filterChoice->Append("-----全部----");
    filterChoice->Append("IPv4");
    filterChoice->Append("IPv6");
    filterChoice->Append("TCP");
    filterChoice->Append("UDP");
    filterChoice->Append("HTTP");
    filterChoice->SetSelection(0);
    // 创建树形分析框
    PacketAnalyse = new wxTreeCtrl(panel, wxID_ANY, wxDefaultPosition, wxSize(400, 200), wxTR_DEFAULT_STYLE | wxTR_HIDE_ROOT);
    wxTreeItemId root = PacketAnalyse->AddRoot("分析信息");
    wxTreeItemId child = PacketAnalyse->AppendItem(root, "示例分析信息"); // 添加示例子节点

    // 创建显示二进制数据的文本框
    PacketBinary = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition, wxSize(600, 200), wxTE_MULTILINE | wxTE_READONLY);
    PacketBinary->SetFont(wxFont(10, wxFONTFAMILY_TELETYPE, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL)); // 设置为等宽字体


    // 使用 sizer 布局
    wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);      // 主垂直布局
    wxBoxSizer* topSizer = new wxBoxSizer(wxHORIZONTAL);     // 顶部水平布局，用于网卡选择、过滤框、按钮

    // 将网卡选择、过滤框、按钮添加到同一行
    topSizer->Add(new wxStaticText(panel, wxID_ANY, "网卡设备："), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    topSizer->Add(choice, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, 10);
    topSizer->Add(new wxStaticText(panel, wxID_ANY, "BPF过滤器："), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    topSizer->Add(PacketFilter, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, 10);
    topSizer->Add(new wxStaticText(panel, wxID_ANY, "数据包筛选："), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    topSizer->Add(filterChoice, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, 10);
    topSizer->Add(startButton, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    topSizer->Add(stopButton, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);

    // 创建一个水平 sizer 用于树形控件和二进制数据显示框
    wxBoxSizer* bottomSizer = new wxBoxSizer(wxHORIZONTAL);
    bottomSizer->Add(PacketAnalyse, 1, wxALL | wxEXPAND | wxCENTER, 10);   // 添加 PacketAnalyse 控件
    bottomSizer->Add(PacketBinary, 1, wxALL | wxEXPAND | wxCENTER, 10);     // 添加 paketBinary 控件

    // 将控件添加到主布局中
    mainSizer->Add(topSizer, 0, wxALL | wxEXPAND, 10);
    mainSizer->Add(packetdisplay, 1, wxALL | wxEXPAND | wxCENTER, 20);  // 网格控件
    mainSizer->Add(bottomSizer, 1, wxALL | wxEXPAND | wxCENTER, 10); // 添加底部的树和文本框

    panel->SetSizerAndFit(mainSizer);  // 设置panel的sizer并自动调整尺寸

    // 绑定事件
    startButton->Bind(wxEVT_BUTTON, &MyFrame::OnStartButtonClicked, this);
    stopButton->Bind(wxEVT_BUTTON, &MyFrame::OnStopButtonClicked, this);
    filterChoice->Bind(wxEVT_CHOICE, &MyFrame::OnFilterChoice, this);
    Bind(wxEVT_MENU, &MyFrame::FileSave, this, wxID_SAVE);
    Bind(wxEVT_MENU, &MyFrame::FileOpen, this,wxID_OPEN);
    packetdisplay->Bind(wxEVT_GRID_SELECT_CELL, &MyFrame::OnGridSelect, this);
 
}
//点击确定后开启网卡设备并开始监听
void MyFrame::OnStartButtonClicked(wxCommandEvent& event) {
    //关闭上一个handle
    if(!handle)
        pcap_close(handle);
    //首先确保选择了一个有效的网卡设备
    if (!isRunning)
    {
        // 获取选中的网络接口
        int selection = choice->GetSelection();
        if (selection == 0)
        {
            wxMessageBox("请选择一个有效网络接口", "警告", wxICON_WARNING);
            return;
        }
        //获取设备
        wxString selectedDev = choice->GetString(selection);
        std::string devicename = std::string(selectedDev.mb_str());
        // 检查 pktdmp 是否为空
        if (pktdmp != nullptr && fileexist==0) {
            // 弹出对话框询问用户是否保存数据包
            int response = wxMessageBox("当前存在已捕获的数据包，是否保存?", "提示", wxYES_NO | wxCANCEL | wxICON_QUESTION);
            if (response == wxYES) {
                // 调用保存数据包函数
                FileSave(event);
                // 清空 pktdmp 和 grid
                ClearPacketData();
            }
            else if (response == wxNO) {
                // 清空 pktdmp 和 grid
                ClearPacketData();
            }
            else {
                return; // 用户选择取消，退出
            }
        }
        else if(pktdmp != nullptr)
            // 清空 pktdmp 和 grid
            ClearPacketData();
        // 启动后台线程
        pcapThread = new PcapThread(this, devicename );
        if (pcapThread->Run() != wxTHREAD_NO_ERROR)
        {
            wxMessageBox("无法启动监听线程", "错误", wxICON_ERROR);
            delete pcapThread;
            pcapThread = nullptr;
            return;
        }
        isRunning = true;
        fileexist = 0;
        // 禁用开始按钮，启用停止按钮,禁用下拉框，禁用过滤输入框
        startButton->Enable(false);
        stopButton->Enable(true);
        choice->Disable();  
        PacketFilter->Disable();
    }
}

//点击停止后恢复状态
void MyFrame::OnStopButtonClicked(wxCommandEvent& event) {
   
    if (isRunning) {
        // 停止线程
        if (pcapThread) {
            pcap_breakloop(handle); // 中断 pcap_loop
        }
        isRunning = false;
    }
        //恢复按钮状态
        startButton->Enable(true);
        stopButton->Enable(false);
        choice->Enable();  
        PacketFilter->Enable();
    
}

//向网格显示框添加一行数据包信息
void MyFrame::AppendText(struct packdisp package)
{
   
    int row = packetdisplay->GetNumberRows();
    packetdisplay->AppendRows(1);  // 添加新行

    // 将结构体字段转换为 wxString 并填充到网格中
    packetdisplay->SetCellValue(row, 0, wxString::Format("%d", package.no));
    packetdisplay->SetCellValue(row, 1, wxString::Format("%s", package.time.c_str()));
    packetdisplay->SetCellValue(row, 2, wxString::Format("%d", package.length));
    packetdisplay->SetCellValue(row, 3, wxString::Format("%s", package.protocol));
    packetdisplay->SetCellValue(row, 4, wxString::Format("%s", package.srcMAC));
    packetdisplay->SetCellValue(row, 5, wxString::Format("%s", package.destMAC));
    packetdisplay->SetCellValue(row, 6, wxString::Format("%s", package.srcIP));
    packetdisplay->SetCellValue(row, 7, wxString::Format("%s", package.destIP));
    

}

//数据包保存
void MyFrame::FileSave(wxCommandEvent& event) {
    if (fileexist == 1)
    {
        wxMessageBox("没有需要保存的文件", "提示", wxICON_INFORMATION);
        return;
    }
    // 创建文件保存对话框
    wxFileDialog saveFileDialog(this, _("保存数据包"), "", "",
        "PCAP files (*.pcap)|*.pcap", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);

    if (saveFileDialog.ShowModal() == wxID_CANCEL) {
        return; // 用户取消
    }

    // 获取文件路径
    wxString filePath = saveFileDialog.GetPath();
    fileexist = 1;
    // 调用数据包保存函数
    if(!Save_Captured_Packets(filePath.ToStdString().c_str(),pktdmp, handle))
        wxMessageBox("保存失败", "警告", wxICON_WARNING);
    else
        wxMessageBox("保存成功", "提示", wxICON_INFORMATION);
}

//数据包打开
void MyFrame::FileOpen(wxCommandEvent& event)
{
    // 检查 pktdmp 是否为空
    if (pktdmp != nullptr && fileexist == 0) {
        // 弹出对话框询问用户是否保存数据包
        int response = wxMessageBox("当前存在已捕获的数据包，是否保存?", "提示", wxYES_NO | wxCANCEL | wxICON_QUESTION);
        if (response == wxYES) {
            // 调用保存数据包函数
            FileSave(event);
            // 清空 pktdmp 和 grid
            ClearPacketData();
        }
        else if (response == wxNO) {
            // 清空 pktdmp 和 grid
            ClearPacketData();
        }
        else {
            return; // 用户选择取消，退出
        }
    }
    else if (pktdmp != nullptr)
        // 清空 pktdmp 和 grid
        ClearPacketData();
    // 创建文件打开对话框
    wxFileDialog openFileDialog(this, _("选择一个PCAP文件"), "", "",
        "PCAP files (*.pcap)|*.pcap", wxFD_OPEN | wxFD_FILE_MUST_EXIST);

    if (openFileDialog.ShowModal() == wxID_CANCEL) {
        return; // 用户取消
    }

    // 获取文件路径
    wxString filePath = openFileDialog.GetPath();
    // 解析PCAP文件并显示在wxGrid中
    pktdmp = LoadAndDisplayPcapFile(filePath.c_str());
    if (pktdmp==NULL) {
        wxMessageBox("无法打开或解析文件", "错误", wxICON_ERROR);
    }
    //分析数据包
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

//根据条件筛选刷新显示
void MyFrame::OnFilterChoice(wxCommandEvent& event) {
    wxString selected = event.GetString();
    
    // 遍历所有行，根据过滤条件显示或隐藏行
    for (int row = 0; row < packetdisplay->GetNumberRows(); ++row) {
        wxString protocol = packetdisplay->GetCellValue(row, 3);
        bool showRow = (selected == "-----全部----") || (protocol.Find(selected) != wxNOT_FOUND);
        
        // 根据条件显示或隐藏行 
        if (showRow) {
            packetdisplay->ShowRow(row);
        }
        else {
            packetdisplay->HideRow(row);
        }
    }

    packetdisplay->Refresh(); // 刷新显示
}

//树形分析框与二进制框显示详细分析信息
void  MyFrame::OnGridSelect(wxGridEvent& event)
{
    int selectedRow = event.GetRow();
    if (selectedRow < 0)
        return;
    //获取当前数据包
    packetdump* currentPacket = pktdmp; 
    int i;
    for (i = 0; i < selectedRow && currentPacket != nullptr; ++i) {
        currentPacket = currentPacket->next;
    }

    if (currentPacket != nullptr) {
        // 清空 wxTreeCtrl
        PacketAnalyse->DeleteAllItems();

        // 添加树形分析信息
        wxTreeItemId root = PacketAnalyse->AddRoot("Packet Details");

        // 获取数据包内容
        const u_char* PacketData = currentPacket->pkt_data; // 数据包内容
        size_t dataSize = currentPacket->header->len; // 数据包长度
        const struct pcap_pkthdr* header = currentPacket->header;//以太网头部
        Packet_Analyse(this, header, PacketData);

        // 格式化二进制数据
        wxString binaryText;
        Binary_Show(&binaryText, PacketData, dataSize);
        PacketBinary->SetValue(binaryText);
    }
}

//清空保存的数据包和显示栏
void MyFrame::ClearPacketData() {
    // 清空数据包链表
    while (pktdmp != nullptr) {
        packetdump* temp = pktdmp;
        pktdmp = pktdmp->next;
        free(temp);
    }

    // 清空 wxGrid 数据
    int rowCount = packetdisplay->GetNumberRows();
    if (rowCount > 0) {
        packetdisplay->DeleteRows(0, rowCount); // 删除所有行
    }
    //清空树形显示栏和二进制文本显示栏
    PacketAnalyse->DeleteAllItems();
    PacketBinary->Clear();

    //序号归零
    no = 1;
}