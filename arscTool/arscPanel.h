#pragma once
#include"ArscAnalyse.h"


// arscPanel �Ի���

class arscPanel : public CDialogEx
{
	DECLARE_DYNAMIC(arscPanel)

public:
	arscPanel(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~arscPanel();

// �Ի�������
	enum { IDD = IDD_DIALOG1 };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	CString strFile;
	CArscAnalyse mArscAnalyse;
public:
	afx_msg void OnBnClickedButton1();
	CString strReport;
	virtual BOOL OnInitDialog();
};
