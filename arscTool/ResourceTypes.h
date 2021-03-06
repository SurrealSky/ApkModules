#pragma once
#include<string>
#include<vector>

enum CHUNK_TYPE{
	RES_NULL_TYPE = 0x0000,
	RES_STRING_POOL_TYPE = 0x0001,
	RES_TABLE_TYPE = 0x0002,
	RES_XML_TYPE = 0x0003,

	// Chunk types in RES_XML_TYPE
	RES_XML_FIRST_CHUNK_TYPE = 0x0100,
	RES_XML_START_NAMESPACE_TYPE = 0x0100,
	RES_XML_END_NAMESPACE_TYPE = 0x0101,
	RES_XML_START_ELEMENT_TYPE = 0x0102,
	RES_XML_END_ELEMENT_TYPE = 0x0103,
	RES_XML_CDATA_TYPE = 0x0104,
	RES_XML_LAST_CHUNK_TYPE = 0x017f,
	// This contains a uint32_t array mapping strings in the string
	// pool back to resource identifiers.  It is optional.
	RES_XML_RESOURCE_MAP_TYPE = 0x0180,

	// Chunk types in RES_TABLE_TYPE
	RES_TABLE_PACKAGE_TYPE = 0x0200,
	RES_TABLE_TYPE_TYPE = 0x0201,
	RES_TABLE_TYPE_SPEC_TYPE = 0x0202,
	RES_TABLE_LIBRARY_TYPE = 0x0203
};

enum DATA_TYPE{
	TYPE_NULL = 0x00,
	TYPE_REFERENCE = 0x01,
	TYPE_ATTRIBUTE = 0x02,
	TYPE_STRING = 0x03,
	TYPE_FLOAT = 0x04,
	TYPE_DIMENSION = 0x05,
	TYPE_FRACTION = 0x06,
	TYPE_FIRST_INT = 0x10,
	TYPE_INT_DEC = 0x10,
	TYPE_INT_HEX = 0x11,
	TYPE_INT_BOOLEAN = 0x12,
	TYPE_FIRST_COLOR_INT = 0x1c,
	TYPE_INT_COLOR_ARGB8 = 0x1c,
	TYPE_INT_COLOR_RGB8 = 0x1d,
	TYPE_INT_COLOR_ARGB4 = 0x1e,
	TYPE_INT_COLOR_RGB4 = 0x1f,
	TYPE_LAST_COLOR_INT = 0x1f,
	TYPE_LAST_INT = 0x1f
};

