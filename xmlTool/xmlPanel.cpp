// xmlPanel.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "xmlTool.h"
#include "xmlPanel.h"
#include "afxdialogex.h"


// xmlPanel �Ի���

IMPLEMENT_DYNAMIC(xmlPanel, CDialogEx)

xmlPanel::xmlPanel(CWnd* pParent /*=NULL*/)
	: CDialogEx(xmlPanel::IDD, pParent)
	, xmlFilePath(_T(""))
	, strXml(_T(""))
	, strMagic(_T(""))
	, strFileSize(_T(""))
{

}

xmlPanel::~xmlPanel()
{
}

void xmlPanel::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_MFCEDITBROWSE1, xmlFilePath);
	DDX_Text(pDX, IDC_EDIT3, strXml);
	DDX_Text(pDX, IDC_EDIT1, strMagic);
	DDX_Text(pDX, IDC_EDIT2, strFileSize);
}


BEGIN_MESSAGE_MAP(xmlPanel, CDialogEx)
	ON_BN_CLICKED(IDC_BUTTON1, &xmlPanel::OnBnClickedButton1)
END_MESSAGE_MAP()


// xmlPanel ��Ϣ�������


void xmlPanel::OnBnClickedButton1()
{
	UpdateData(TRUE);

	//��Ҫ�ȴ��̵߳ȴ����
	if (mXmlAnalyse.isAnalysised)
	{
		mXmlAnalyse.xmlUnload();
	}

	if (xmlFilePath.GetLength() == 0)
	{
		::MessageBox(this->m_hWnd, L"��ѡ��Ҫ�������ļ�", L"����", MB_OK);
		return;
	}

	//�����ļ�
	if (!mXmlAnalyse.xmlLoadFile(xmlFilePath.GetBuffer(0),L"r"))     //ֻ����ʽ���ļ�
	{
		::MessageBox(this->m_hWnd, L"����xml�ļ�ʧ��", L"����", MB_OK);
		return;
	}

	//��ʼ����
	if (mXmlAnalyse.Analysis())
	{
		mXmlAnalyse.isAnalysised=true;
	}
	else
	{
		::MessageBox(this->m_hWnd, L"����ʧ��", L"����", MB_OK);
		return;
	}
	//��ʼ����xml
	strMagic.Format(L"%08XH", mXmlAnalyse.mCtx.xml.magic);
	strFileSize.Format(L"%d B", mXmlAnalyse.mCtx.size);
	std::wstring str = mXmlAnalyse.createXml();
	strXml.Append(str.c_str(), str.size());
	UpdateData(FALSE);
}
