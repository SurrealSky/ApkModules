#pragma once
#include"xmlAnalyse.h"

// xmlPanel �Ի���

class xmlPanel : public CDialogEx
{
	DECLARE_DYNAMIC(xmlPanel)

public:
	xmlPanel(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~xmlPanel();

// �Ի�������
	enum { IDD = IDD_DIALOG1 };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	CXmlAnalyse mXmlAnalyse;
	CString xmlFilePath;
	CString strXml;
	CString strMagic;
	CString strFileSize;
public:
	afx_msg void OnBnClickedButton1();
};
