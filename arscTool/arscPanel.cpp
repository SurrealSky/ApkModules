// arscPanel.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "arscTool.h"
#include "arscPanel.h"
#include "afxdialogex.h"


// arscPanel �Ի���

IMPLEMENT_DYNAMIC(arscPanel, CDialogEx)

arscPanel::arscPanel(CWnd* pParent /*=NULL*/)
	: CDialogEx(arscPanel::IDD, pParent)
	, strFile(_T(""))
	, strReport(_T(""))
{

}

arscPanel::~arscPanel()
{
}

void arscPanel::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_MFCEDITBROWSE1, strFile);
	DDX_Text(pDX, IDC_EDIT3, strReport);
}


BEGIN_MESSAGE_MAP(arscPanel, CDialogEx)
	ON_BN_CLICKED(IDC_BUTTON1, &arscPanel::OnBnClickedButton1)
END_MESSAGE_MAP()


// arscPanel ��Ϣ�������

//����
void arscPanel::OnBnClickedButton1()
{
	UpdateData(TRUE);

	//��Ҫ�ȴ��̵߳ȴ����
	if (mArscAnalyse.isAnalysised)
	{
		mArscAnalyse.arscUnload();
	}

	if (strFile.GetLength() == 0)
	{
		::MessageBox(this->m_hWnd, L"��ѡ��Ҫ�������ļ�", L"����", MB_OK);
		return;
	}

	//�����ļ�
	if (!mArscAnalyse.arscLoadFile(strFile.GetBuffer(0), L"r"))     //ֻ����ʽ���ļ�
	{
		::MessageBox(this->m_hWnd, L"����arsc�ļ�ʧ��", L"����", MB_OK);
		return;
	}

	//��ʼ����
	if (mArscAnalyse.Analysis())
	{
		mArscAnalyse.isAnalysised = true;
		std::wstring str = mArscAnalyse.doReport();
		strReport = L"";
		strReport.Append(str.c_str(), str.size());
		UpdateData(FALSE);
	}
	else
	{
		::MessageBox(this->m_hWnd, L"����ʧ��", L"����", MB_OK);
		return;
	}
}


BOOL arscPanel::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  �ڴ���Ӷ���ĳ�ʼ��
	strFile = L"C:\\Users\\Administrator\\Desktop\\resources.arsc";
	UpdateData(FALSE);
	return TRUE;  // return TRUE unless you set the focus to a control
	// �쳣:  OCX ����ҳӦ���� FALSE
}
