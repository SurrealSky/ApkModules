// dexTool.h : dexTool DLL ����ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CdexToolApp
// �йش���ʵ�ֵ���Ϣ������� dexTool.cpp
//

class CdexToolApp : public CWinApp
{
public:
	CdexToolApp();

// ��д
public:
	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP()
	afx_msg void OnApkDex();
};
