// arscTool.h : arscTool DLL ����ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CarscToolApp
// �йش���ʵ�ֵ���Ϣ������� arscTool.cpp
//

class CarscToolApp : public CWinApp
{
public:
	CarscToolApp();

// ��д
public:
	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP()
	afx_msg void OnApkArsc();
};
