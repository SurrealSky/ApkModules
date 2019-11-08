#pragma once
#include"ResStringPoolChunk.h"
#include"ResValue.h"

typedef struct
{
	int ident;
}ResTableRef;

class ResTableEntry
{
public:

	ResTableEntry()
	{
	}

	virtual ~ResTableEntry()
	{
	}
public:
	unsigned int entryId;//�Լ���ӵı��entry�ڵ�ǰ�������е�ƫ��
public:
	short size;
	short flags;
	ResStringPoolRef key;
	ResValue	resValue;
};

