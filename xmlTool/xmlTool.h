// xmlTool.h : xmlTool DLL ����ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CxmlToolApp
// �йش���ʵ�ֵ���Ϣ������� xmlTool.cpp
//

class CxmlToolApp : public CWinApp
{
public:
	CxmlToolApp();

// ��д
public:
	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP()
	afx_msg void OnXml();
};
