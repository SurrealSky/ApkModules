#pragma once
#include "ResChunkBase.h"
class ResTableChunk :
	public ResChunkBase
{
public:

	ResTableChunk()
	{
	}

	virtual ~ResTableChunk()
	{
	}
public:
	unsigned int packageCount;   // ���������Դ���ĸ���
};

