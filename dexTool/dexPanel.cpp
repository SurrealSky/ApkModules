// dexPanel.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "dexTool.h"
#include "dexPanel.h"
#include "afxdialogex.h"


// dexPanel �Ի���

IMPLEMENT_DYNAMIC(dexPanel, CDialogEx)

dexPanel::dexPanel(CWnd* pParent /*=NULL*/)
	: CDialogEx(dexPanel::IDD, pParent)
	, strFile(_T(""))
	, strReport(_T(""))
{

}

dexPanel::~dexPanel()
{
}

void dexPanel::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_MFCEDITBROWSE1, strFile);
	DDX_Text(pDX, IDC_EDIT3, strReport);
}


BEGIN_MESSAGE_MAP(dexPanel, CDialogEx)
	ON_BN_CLICKED(IDC_BUTTON1, &dexPanel::OnBnClickedButton1)
END_MESSAGE_MAP()


// dexPanel ��Ϣ�������

//����dex�ļ�
void dexPanel::OnBnClickedButton1()
{
	UpdateData(TRUE);
	//��Ҫ�ȴ��̵߳ȴ����
	if (mDexAnalyse.isAnalysised)
	{
		mDexAnalyse.dexUnload();
	}

	if (strFile.GetLength() == 0)
	{
		::MessageBox(this->m_hWnd, L"��ѡ��Ҫ�������ļ�", L"����", MB_OK);
		return;
	}

	//�����ļ�
	if (!mDexAnalyse.dexLoadFile(strFile.GetBuffer(0), L"r"))     //ֻ����ʽ���ļ�
	{
		::MessageBox(this->m_hWnd, L"����dex�ļ�ʧ��", L"����", MB_OK);
		return;
	}

	//��ʼ����
	if (mDexAnalyse.Analysis())
	{
		mDexAnalyse.isAnalysised = true;
		std::wstring str = mDexAnalyse.doReport();
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


BOOL dexPanel::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  �ڴ���Ӷ���ĳ�ʼ��
	strFile = L"C:\\Users\\Administrator\\Desktop\\1.dex";
	UpdateData(FALSE);
	return TRUE;  // return TRUE unless you set the focus to a control
	// �쳣:  OCX ����ҳӦ���� FALSE
}
