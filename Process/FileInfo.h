#pragma once
#include <wincrypt.h>
#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

typedef struct {
    LPWSTR lpszProgramName;
    LPWSTR lpszPublisherLink;
    LPWSTR lpszMoreInfoLink;
} SPROG_PUBLISHERINFO, *PSPROG_PUBLISHERINFO;
struct DigitalSignatureInfo
{
	wstring ProgramName;
	wstring PublisherLink;
	wstring MoreInfoLink;
	wstring SignerSerialNumber;
	wstring SignerIssuerName;
	wstring SignerSubjectName;
	wstring TimeStampSerialNumber;
	wstring TimeStampIssuerName;
	wstring TimeStampSubjectName;
	SYSTEMTIME DateofTimeStamp;
};

enum { 
 COMPANYNAME,
 FILESVERSION,
 LEGALCOPYRIGHT,
 PRIVATEBUILD,
 COMMENTS,
 INTERNALNAME,
 PRODUCTNAME,
 PRODUCTSVERSION,
 FILEDESCRIPTION,
 LEGALTRADEMARKS,
 ORIGINALFILENAME,
 SPECIALBUILD,
 VERSIONCOUNT
};
bool GetDigitalSignature(TCHAR* m_Path,DigitalSignatureInfo * pInfo);
BOOL PrintCertificateInfo(PCCERT_CONTEXT pCertContext,DigitalSignatureInfo * pInfo,TCHAR * pType);
LPWSTR AllocateAndCopyWideString(LPCWSTR inputString);
BOOL GetProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo,PSPROG_PUBLISHERINFO Info);
BOOL GetDateOfTimeStamp(PCMSG_SIGNER_INFO pSignerInfo, SYSTEMTIME *st);
BOOL GetTimeStampSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO *pCounterSignerInfo);
BOOL GetFileVersion(TCHAR * pPath,wstring * pFileVersionStr);
//BOOL GetFileOwner(TCHAR * pPath,wstring * pDomainName,wstring * pAcctName);
BOOL GetFileTimeInfo(TCHAR * pFilePath,FILETIME *pCreateTime,FILETIME *pAccessTime,FILETIME *pWriteTime);
LONGLONG GetFileSizeInfo(TCHAR * pFilePath);