#pragma once
#include<map>
#include "ResChunkBase.h"

typedef struct
{
	int index;
}ResStringPoolRef;

typedef struct
{
	ResStringPoolRef name;
	int firstChar;
	int lastChar;
}ResStringPoolSpan;

typedef struct{
	std::wstring str;
	ResStringPoolSpan	resStringPoolSpan;

}ResStringStyles;

class ResStringPoolChunk :
	public ResChunkBase
{
public:

	ResStringPoolChunk()
	{
	}

	virtual ~ResStringPoolChunk()
	{
	}
public:
	int stringCount;        // �ַ����ĸ���
	int styleCount;         // �ַ�����ʽ�ĸ���
	int flags;              // �ַ���������,��ȡֵ����0x000(UTF-16),0x001(�ַ�����������)��0X100(UTF-8)�����ǵ����ֵ
	int stringsStart;       // �ַ������ݿ��������ͷ���ľ���
	int stylesStart;        // �ַ�����ʽ���������ͷ���ľ���
	std::map<unsigned int, std::wstring> strings;
};

