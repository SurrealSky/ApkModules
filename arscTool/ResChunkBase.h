#pragma once
class ResChunkBase
{
public:

	ResChunkBase()
	{
	}

	virtual ~ResChunkBase()
	{
	}
public:
	unsigned short wChunkType;	 // CHUNK_TYPE
	unsigned short wHeaderSize;			// ��ǰChunk��head��С
	unsigned int dwChunkSize;	// ��ǰChunk��С
};

