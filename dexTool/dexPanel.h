#pragma once
#include"DexAnalyse.h"


// dexPanel �Ի���

class dexPanel : public CDialogEx
{
	DECLARE_DYNAMIC(dexPanel)

public:
	dexPanel(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~dexPanel();

// �Ի�������
	enum { IDD = IDD_DIALOG1 };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	virtual BOOL OnInitDialog();
	CString strFile;
public:
	CDexAnalyse mDexAnalyse;
	CString strReport;
};
