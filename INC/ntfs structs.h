#pragma once

union NTFS_FILE_ID 
{
	LONGLONG IndexNumber;

	struct  
	{
		LONGLONG MftRecordIndex : 48;
		LONGLONG SequenceNumber : 16;
	};
};

struct NTFS_RECORD_HEADER 
{
	enum {
		FILE = 'ELIF',
		INDX = 'XDNI',
		BAAD = 'DAAB',
		HOLE = 'ELOH',
		CHKD = 'DKHC'
	} Type;
	USHORT UsaOffset;
	USHORT UsaCount;
	USN Usn;
};

struct NTFS_FILE_RECORD_HEADER : public NTFS_RECORD_HEADER
{
	USHORT SequenceNumber;
	USHORT LinkCount;
	USHORT AttributesOffset;
	USHORT Flags;
	ULONG BytesInUse;
	ULONG BytesAllocated;
	ULONGLONG BaseFileRecord;
	USHORT NextAttributeNumber;

	enum{
		flgInUse = 1, flgDirectory = 2
	};
};

struct NTFS_ATTRIBUTE 
{
	enum ATTRIBUTE_TYPE {
		StandardInformation = 0x10,
		AttributeList = 0x20,
		FileName = 0x30,
		ObjectId = 0x40,
		SecurityDescriptor = 0x50,
		VolumeName = 0x60,
		VolumeInformation = 0x70,
		Data = 0x80,
		IndexRoot = 0x90,
		IndexAllocation = 0xa0,
		Bitmap = 0xb0,
		ReparsePoint = 0xc0,
		EAInformation = 0xd0,
		EA = 0xe0,
		PropertySet = 0xf0,
		LoggedUtilityStream = 0x100,
		StopTag = MAXDWORD
	} Type;
	ULONG Length;
	BOOLEAN Nonresident;
	UCHAR NameLength;
	USHORT NameOffset;
	USHORT Flags;// 1 = Compresed
	USHORT AttributeNumber;
};

struct NTFS_RESIDENT_ATTRIBUTE : public NTFS_ATTRIBUTE 
{
	ULONG ValueLength;
	USHORT ValueOffset;
	USHORT Flags;
};

struct NTFS_NONRESIDENT_ATTRIBUTE : public NTFS_ATTRIBUTE 
{
	LONGLONG LowVcn;
	LONGLONG HighVcn;
	USHORT RunArrayOffset;
	UCHAR CompressionUnit;
	UCHAR Unknown[5];
	LONGLONG AllocationSize;
	LONGLONG DataSize;
	LONGLONG InitializedSize;
	LONGLONG CompressedSize;
};

struct NTFS_ATTRIBUTE_LIST
{
	NTFS_ATTRIBUTE::ATTRIBUTE_TYPE Type;
	USHORT Length;
	UCHAR NameLength;
	UCHAR NameOffset;
	LONGLONG LowVcn;
	NTFS_FILE_ID FileReferenceNumber;
	USHORT AttributeNumber;
	USHORT Unknown[3];
};

struct NTFS_STANDARD_ATTRIBUTE 
{
	LONGLONG CreationTime;
	LONGLONG ChangeTime;
	LONGLONG LastWriteTime;
	LONGLONG LastAccessTime;
	ULONG FileAttributes;
	ULONG Unknown[3];
	ULONG QuotaId;
	ULONG SecurityId;
	ULONGLONG QuotaChange;
	USN Usn;
};

struct NTFS_FILENAME_ATTRIBUTE
{
	NTFS_FILE_ID DirectoryId;
	LONGLONG CreationTime;
	LONGLONG ChangeTime;
	LONGLONG LastWriteTime;
	LONGLONG LastAccessTime;
	LONGLONG AllocationSize;
	LONGLONG DataSize;
	ULONG FileAttributes;
	ULONG EaSize;
	UCHAR FileNameLength;
	UCHAR NameType;
	WCHAR FileName[];

	enum {
		systemName , longName, shortName, systemName2
	};
};