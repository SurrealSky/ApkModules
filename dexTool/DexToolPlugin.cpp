#include "stdafx.h"
#include "DexToolPlugin.h"


IMPLEMENT_PLUGIN(DexToolPlugin)

void DexToolPlugin::Init()
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());

	// merge menu
	CMenu append;
	append.LoadMenu(IDR_MENU1);
	MergeMenu(&append, TRUE);
}

void DexToolPlugin::Query(CPluginInfo& plugininfo)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());

	plugininfo.m_strName = _T("dex Tool");
	plugininfo.m_strBlurb = _T("dex��������");
	plugininfo.m_strHelp = _T("����");
	plugininfo.m_strAuthor = _T("wangzha");
	plugininfo.m_strCopyRight = _T("Copyright wangzha");
	plugininfo.m_strDate = _T("2018.04.04");
	plugininfo.m_strMenuLabel = "apk";
}

