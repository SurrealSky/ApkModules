#pragma once
#include"h_xml.h"
class CXmlAnalyse
{
public:
	CXmlAnalyse();
	~CXmlAnalyse();
public:
	xml_ctx_t	mCtx;
	bool		isAnalysised;
public:
	//��ʼ��
	bool xmlLoadFile(const wchar_t *lpPath, const wchar_t *lpModel);
	bool xmlUnload();
public://��������
	bool	Analysis();
	std::wstring getAttrType(unsigned int);
	std::wstring getAttributeData(unsigned int,unsigned int);
	std::wstring createXml();
};

