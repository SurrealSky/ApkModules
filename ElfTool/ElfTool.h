// ElfTool.h : ElfTool DLL ����ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CElfToolApp
// �йش���ʵ�ֵ���Ϣ������� ElfTool.cpp
//

class CElfToolApp : public CWinApp
{
public:
	CElfToolApp();

// ��д
public:
	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP()
	afx_msg void OnApkElf();
};
