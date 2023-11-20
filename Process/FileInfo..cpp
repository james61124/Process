#include "stdafx.h"
#include "FileInfo.h"
#include <wintrust.h>
#include <aclapi.h>
#pragma comment(lib,"Crypt32.lib")
#pragma  comment(lib, "VERSION.LIB")

bool GetDigitalSignature(TCHAR* m_Path,DigitalSignatureInfo * pInfo)
{
	WCHAR szFileName[MAX_PATH]; 
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL; 
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL fResult;   
    DWORD dwEncoding, dwContentType, dwFormatType;
    PCMSG_SIGNER_INFO pSignerInfo = NULL;
    PCMSG_SIGNER_INFO pCounterSignerInfo = NULL;
    DWORD dwSignerInfo;
    CERT_INFO CertInfo;     
    SPROG_PUBLISHERINFO ProgPubInfo;
    SYSTEMTIME st;

    ZeroMemory(&ProgPubInfo, sizeof(ProgPubInfo));
	bool ret = true;
    __try
    {

#ifdef UNICODE
		if(_waccess(m_Path,00))
		{
			//_tprintf(_T("No File\n"));
            return false;
		}
        lstrcpynW(szFileName, m_Path, MAX_PATH);	
#else
        if (mbstowcs(szFileName, m_Path, MAX_PATH) == -1)
        {
            printf("Unable to convert to unicode.\n");
            __leave;
        }
#endif
        // Get message handle and store handle from the signed file.
        fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                                   szFileName,
                                   CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                                   CERT_QUERY_FORMAT_FLAG_BINARY,
                                   0,
                                   &dwEncoding,
                                   &dwContentType,
                                   &dwFormatType,
                                   &hStore,
                                   &hMsg,
                                   NULL);
        if (!fResult)
        {
            //_tprintf(_T("CryptQueryObject failed with %x\n"), GetLastError());
			ret = false;
            __leave;
        }

        // Get signer information size.
        fResult = CryptMsgGetParam(hMsg, 
                                   CMSG_SIGNER_INFO_PARAM, 
                                   0, 
                                   NULL, 
                                   &dwSignerInfo);
        if (!fResult)
        {
           //_tprintf(_T("CryptMsgGetParam failed with %x\n"), GetLastError());
            __leave;
        }

        // Allocate memory for signer information.
        pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
        if (!pSignerInfo)
        {
            //_tprintf(_T("Unable to allocate memory for Signer Info.\n"));
            __leave;
        }

        // Get Signer Information.
        fResult = CryptMsgGetParam(hMsg, 
                                   CMSG_SIGNER_INFO_PARAM, 
                                   0, 
                                   (PVOID)pSignerInfo, 
                                   &dwSignerInfo);
        if (!fResult)
        {
            //_tprintf(_T("CryptMsgGetParam failed with %x\n"), GetLastError());
            __leave;
        }
        
        // Get program name and publisher information from 
        // signer info structure.
        if (GetProgAndPublisherInfo(pSignerInfo, &ProgPubInfo))
        {
            if (ProgPubInfo.lpszProgramName != NULL)
            {
                //wprintf(L"Program Name : %s\n",
                 //   ProgPubInfo.lpszProgramName);
				//swprintf_s(pInfo->ProgramName,256,L"%s",ProgPubInfo.lpszProgramName);
				pInfo->ProgramName = ProgPubInfo.lpszProgramName;
            }

            if (ProgPubInfo.lpszPublisherLink != NULL)
            {
                //wprintf(L"Publisher Link : %s\n",
                //    ProgPubInfo.lpszPublisherLink);
				//swprintf_s(pInfo->PublisherLink,256,L"%s",ProgPubInfo.lpszPublisherLink);
				pInfo->PublisherLink = ProgPubInfo.lpszPublisherLink;
            }

            if (ProgPubInfo.lpszMoreInfoLink != NULL)
            {
                //wprintf(L"MoreInfo Link : %s\n",
                //    ProgPubInfo.lpszMoreInfoLink);
				//swprintf_s(pInfo->MoreInfoLink,256,L"%s",ProgPubInfo.lpszMoreInfoLink);
				pInfo->MoreInfoLink = ProgPubInfo.lpszMoreInfoLink;
            }
        }

        //_tprintf(_T("\n"));

        // Search for the signer certificate in the temporary 
        // certificate store.
        CertInfo.Issuer = pSignerInfo->Issuer;
        CertInfo.SerialNumber = pSignerInfo->SerialNumber;

        pCertContext = CertFindCertificateInStore(hStore,
                                                  ENCODING,
                                                  0,
                                                  CERT_FIND_SUBJECT_CERT,
                                                  (PVOID)&CertInfo,
                                                  NULL);
        if (!pCertContext)
        {
            //_tprintf(_T("CertFindCertificateInStore failed with %x\n"),
            //    GetLastError());
            __leave;
        }

        // Print Signer certificate information.
       // _tprintf(_T("Signer Certificate:\n\n"));        
        PrintCertificateInfo(pCertContext,pInfo, const_cast<wchar_t*>(_T("Signer")));
        //_tprintf(_T("\n"));
        
        // Get the timestamp certificate signerinfo structure.
        if (GetTimeStampSignerInfo(pSignerInfo, &pCounterSignerInfo))
        {
            // Search for Timestamp certificate in the temporary
            // certificate store.
            CertInfo.Issuer = pCounterSignerInfo->Issuer;
            CertInfo.SerialNumber = pCounterSignerInfo->SerialNumber;

            pCertContext = CertFindCertificateInStore(hStore,
                                                ENCODING,
                                                0,
                                                CERT_FIND_SUBJECT_CERT,
                                                (PVOID)&CertInfo,
                                                NULL);
            if (!pCertContext)
            {
                _tprintf(_T("CertFindCertificateInStore failed with %x\n"),
                    GetLastError());
                __leave;
            }

            // Print timestamp certificate information.
            //_tprintf(_T("TimeStamp Certificate:\n\n"));
            PrintCertificateInfo(pCertContext,pInfo, const_cast<wchar_t*>(_T("TimeStamp")));
            //_tprintf(_T("\n"));

            // Find Date of timestamp.
            if (GetDateOfTimeStamp(pCounterSignerInfo, &st))
            {
				pInfo->DateofTimeStamp = st;
                //_tprintf(_T("Date of TimeStamp : %02d/%02d/%04d %02d:%02d\n"),
                //                            st.wMonth,
                //                            st.wDay,
                //                            st.wYear,
                //                            st.wHour,
                //                            st.wMinute);
				//swprintf_s(pInfo->DateofTimeStamp,256,_T("%02d/%02d/%04d %02d:%02d"),st.wMonth,st.wDay,st.wYear,st.wHour,st.wMinute);
            }
            //_tprintf(_T("\n"));
        }
    }
    __finally
    {               
        // Clean up.
        if (ProgPubInfo.lpszProgramName != NULL)
            LocalFree(ProgPubInfo.lpszProgramName);
        if (ProgPubInfo.lpszPublisherLink != NULL)
            LocalFree(ProgPubInfo.lpszPublisherLink);
        if (ProgPubInfo.lpszMoreInfoLink != NULL)
            LocalFree(ProgPubInfo.lpszMoreInfoLink);

        if (pSignerInfo != NULL) LocalFree(pSignerInfo);
        if (pCounterSignerInfo != NULL) LocalFree(pCounterSignerInfo);
        if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
        if (hStore != NULL) CertCloseStore(hStore, 0);
        if (hMsg != NULL) CryptMsgClose(hMsg);
    }
	return ret;
}
BOOL PrintCertificateInfo(PCCERT_CONTEXT pCertContext,DigitalSignatureInfo * pInfo,TCHAR * pType)
{
    BOOL fReturn = FALSE;
    LPTSTR szName = NULL;
    DWORD dwData;

    __try
    {
        // Print Serial Number.
       // _tprintf(_T("Serial Number: "));
		if(!_tcscmp(pType,_T("Signer")))
		{
			pInfo->SignerSerialNumber = L"";
			//memset(pInfo->SignerSerialNumber,'\0',256);
			dwData = pCertContext->pCertInfo->SerialNumber.cbData;
			for (DWORD n = 0; n < dwData; n++)
			{
				//_tprintf(_T("%02x "),
				  //pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)]);
				TCHAR* cstr = new TCHAR[10];
				swprintf_s(cstr,10,_T("%02x "),pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)]);
				//_tcscat_s(pInfo->SignerSerialNumber,cstr);
				pInfo->SignerSerialNumber += cstr;
				delete [] cstr;
			}
		}
		else if(!_tcscmp(pType,_T("TimeStamp")))
		{
			//memset(pInfo->TimeStampSerialNumber,'\0',256);
			pInfo->TimeStampSerialNumber = L"";
			dwData = pCertContext->pCertInfo->SerialNumber.cbData;
			for (DWORD n = 0; n < dwData; n++)
			{
				//_tprintf(_T("%02x "),
				  //pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)]);
				TCHAR* cstr = new TCHAR[10];
				swprintf_s(cstr,10,_T("%02x "),pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)]);
				//_tcscat_s(pInfo->TimeStampSerialNumber,cstr);
				pInfo->TimeStampSerialNumber += cstr;
				delete [] cstr;
			}
		}
       // _tprintf(_T("\n"));

        // Get Issuer name size.
        if (!(dwData = CertGetNameString(pCertContext, 
                                         CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                         CERT_NAME_ISSUER_FLAG,
                                         NULL,
                                         NULL,
                                         0)))
        {
           // _tprintf(_T("CertGetNameString failed.\n"));
            __leave;
        }

        // Allocate memory for Issuer name.
        szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
        if (!szName)
        {
           // _tprintf(_T("Unable to allocate memory for issuer name.\n"));
            __leave;
        }

        // Get Issuer name.
        if (!(CertGetNameString(pCertContext, 
                                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                CERT_NAME_ISSUER_FLAG,
                                NULL,
                                szName,
                                dwData)))
        {
            //_tprintf(_T("CertGetNameString failed.\n"));
            __leave;
        }

        // print Issuer name.
        //_tprintf(_T("Issuer Name: %s\n"), szName);
		if(!_tcscmp(pType,_T("Signer")))
		{
			//swprintf_s(pInfo->SignerIssuerName,256,_T("%s"),szName);
			pInfo->SignerIssuerName = szName;
		}
		else if(!_tcscmp(pType,_T("TimeStamp")))
		{
			//swprintf_s(pInfo->TimeStampIssuerName,256,_T("%s"),szName);
			pInfo->TimeStampIssuerName = szName;
		}
        LocalFree(szName);
        szName = NULL;

        // Get Subject name size.
        if (!(dwData = CertGetNameString(pCertContext, 
                                         CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                         0,
                                         NULL,
                                         NULL,
                                         0)))
        {
            //_tprintf(_T("CertGetNameString failed.\n"));
            __leave;
        }

        // Allocate memory for subject name.
        szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
        if (!szName)
        {
            //_tprintf(_T("Unable to allocate memory for subject name.\n"));
            __leave;
        }

        // Get subject name.
        if (!(CertGetNameString(pCertContext, 
                                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                0,
                                NULL,
                                szName,
                                dwData)))
        {
            //_tprintf(_T("CertGetNameString failed.\n"));
            __leave;
        }

        // Print Subject Name.
        //_tprintf(_T("Subject Name: %s\n"), szName);
		if(!_tcscmp(pType,_T("Signer")))
		{
			//swprintf_s(pInfo->SignerSubjectName,256,_T("%s"),szName);
			pInfo->SignerSubjectName = szName;
		}
		else if(!_tcscmp(pType,_T("TimeStamp")))
		{
			//swprintf_s(pInfo->TimeStampSubjectName,256,_T("%s"),szName);
			pInfo->TimeStampSubjectName = szName;
		}
        fReturn = TRUE;
    }
    __finally
    {
        if (szName != NULL) LocalFree(szName);
    }

    return fReturn;
}
LPWSTR AllocateAndCopyWideString(LPCWSTR inputString)
{
    LPWSTR outputString = NULL;

    outputString = (LPWSTR)LocalAlloc(LPTR,
        (wcslen(inputString) + 1) * sizeof(WCHAR));
    if (outputString != NULL)
    {
        lstrcpyW(outputString, inputString);
    }
    return outputString;
}

BOOL GetProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo,
                             PSPROG_PUBLISHERINFO Info)
{
    BOOL fReturn = FALSE;
    PSPC_SP_OPUS_INFO OpusInfo = NULL;  
    DWORD dwData;
    BOOL fResult;
    
    __try
    {
        // Loop through authenticated attributes and find
        // SPC_SP_OPUS_INFO_OBJID OID.
        for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
        {           
            if (lstrcmpA(SPC_SP_OPUS_INFO_OBJID, 
                        pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
            {
                // Get Size of SPC_SP_OPUS_INFO structure.
                fResult = CryptDecodeObject(ENCODING,
                            SPC_SP_OPUS_INFO_OBJID,
                            pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
                            pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
                            0,
                            NULL,
                            &dwData);
                if (!fResult)
                {
                    _tprintf(_T("CryptDecodeObject failed with %x\n"),
                        GetLastError());
                    __leave;
                }

                // Allocate memory for SPC_SP_OPUS_INFO structure.
                OpusInfo = (PSPC_SP_OPUS_INFO)LocalAlloc(LPTR, dwData);
                if (!OpusInfo)
                {
                    _tprintf(_T("Unable to allocate memory for Publisher Info.\n"));
                    __leave;
                }

                // Decode and get SPC_SP_OPUS_INFO structure.
                fResult = CryptDecodeObject(ENCODING,
                            SPC_SP_OPUS_INFO_OBJID,
                            pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
                            pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
                            0,
                            OpusInfo,
                            &dwData);
                if (!fResult)
                {
                    _tprintf(_T("CryptDecodeObject failed with %x\n"),
                        GetLastError());
                    __leave;
                }

                // Fill in Program Name if present.
                if (OpusInfo->pwszProgramName)
                {
                    Info->lpszProgramName =
                        AllocateAndCopyWideString(OpusInfo->pwszProgramName);
                }
                else
                    Info->lpszProgramName = NULL;

                // Fill in Publisher Information if present.
                if (OpusInfo->pPublisherInfo)
                {

                    switch (OpusInfo->pPublisherInfo->dwLinkChoice)
                    {
                        case SPC_URL_LINK_CHOICE:
                            Info->lpszPublisherLink =
                                AllocateAndCopyWideString(OpusInfo->pPublisherInfo->pwszUrl);
                            break;

                        case SPC_FILE_LINK_CHOICE:
                            Info->lpszPublisherLink =
                                AllocateAndCopyWideString(OpusInfo->pPublisherInfo->pwszFile);
                            break;

                        default:
                            Info->lpszPublisherLink = NULL;
                            break;
                    }
                }
                else
                {
                    Info->lpszPublisherLink = NULL;
                }

                // Fill in More Info if present.
                if (OpusInfo->pMoreInfo)
                {
                    switch (OpusInfo->pMoreInfo->dwLinkChoice)
                    {
                        case SPC_URL_LINK_CHOICE:
                            Info->lpszMoreInfoLink =
                                AllocateAndCopyWideString(OpusInfo->pMoreInfo->pwszUrl);
                            break;

                        case SPC_FILE_LINK_CHOICE:
                            Info->lpszMoreInfoLink =
                                AllocateAndCopyWideString(OpusInfo->pMoreInfo->pwszFile);
                            break;

                        default:
                            Info->lpszMoreInfoLink = NULL;
                            break;
                    }
                }               
                else
                {
                    Info->lpszMoreInfoLink = NULL;
                }

                fReturn = TRUE;

                break; // Break from for loop.
            } // lstrcmp SPC_SP_OPUS_INFO_OBJID                 
        } // for 
    }
    __finally
    {
        if (OpusInfo != NULL) LocalFree(OpusInfo);      
    }

    return fReturn;
}

BOOL GetDateOfTimeStamp(PCMSG_SIGNER_INFO pSignerInfo, SYSTEMTIME *st)
{   
    BOOL fResult;
    FILETIME lft, ft;   
    DWORD dwData;
    BOOL fReturn = FALSE;
    
    // Loop through authenticated attributes and find
    // szOID_RSA_signingTime OID.
    for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
    {           
        if (lstrcmpA(szOID_RSA_signingTime, 
                    pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
        {               
            // Decode and get FILETIME structure.
            dwData = sizeof(ft);
            fResult = CryptDecodeObject(ENCODING,
                        szOID_RSA_signingTime,
                        pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
                        pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
                        0,
                        (PVOID)&ft,
                        &dwData);
            if (!fResult)
            {
                _tprintf(_T("CryptDecodeObject failed with %x\n"),
                    GetLastError());
                break;
            }

            // Convert to local time.
            FileTimeToLocalFileTime(&ft, &lft);
            FileTimeToSystemTime(&lft, st);

            fReturn = TRUE;

            break; // Break from for loop.
                        
        } //lstrcmp szOID_RSA_signingTime
    } // for 

    return fReturn;
}

BOOL GetTimeStampSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO *pCounterSignerInfo)
{   
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL fReturn = FALSE;
    BOOL fResult;       
    DWORD dwSize;   

    __try
    {
        *pCounterSignerInfo = NULL;

        // Loop through unathenticated attributes for
        // szOID_RSA_counterSign OID.
        for (DWORD n = 0; n < pSignerInfo->UnauthAttrs.cAttr; n++)
        {
            if (lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId, 
                         szOID_RSA_counterSign) == 0)
            {
                // Get size of CMSG_SIGNER_INFO structure.
                fResult = CryptDecodeObject(ENCODING,
                           PKCS7_SIGNER_INFO,
                           pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
                           pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
                           0,
                           NULL,
                           &dwSize);
                if (!fResult)
                {
                    _tprintf(_T("CryptDecodeObject failed with %x\n"),
                        GetLastError());
                    __leave;
                }

                // Allocate memory for CMSG_SIGNER_INFO.
                *pCounterSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSize);
                if (!*pCounterSignerInfo)
                {
                    _tprintf(_T("Unable to allocate memory for timestamp info.\n"));
                    __leave;
                }

                // Decode and get CMSG_SIGNER_INFO structure
                // for timestamp certificate.
                fResult = CryptDecodeObject(ENCODING,
                           PKCS7_SIGNER_INFO,
                           pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
                           pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
                           0,
                           (PVOID)*pCounterSignerInfo,
                           &dwSize);
                if (!fResult)
                {
                    _tprintf(_T("CryptDecodeObject failed with %x\n"),
                        GetLastError());
                    __leave;
                }

                fReturn = TRUE;
                
                break; // Break from for loop.
            }           
        }
    }
    __finally
    {
        // Clean up.
        if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
    }

    return fReturn;
}

BOOL GetFileVersion(TCHAR * pPath,wstring * pFileVersionStr)
{
	wchar_t /*cPath[MAX_PATH],*/ cSubBlock[MAX_PATH];
	DWORD dwHandle, dwInfoSize, dwTrans;
	UINT uTranslate = 0, uBytes = 0;
	DWORD *dwTranslation = NULL;
	WCHAR *cpBuffer = NULL;

	//Get file version size 
	dwInfoSize = GetFileVersionInfoSize(pPath, &dwHandle);
	if(dwInfoSize == 0)
	{
		//printf("ERROR : The file resource version size is error.\n");
		return FALSE;
	}

	//Allocate buffer and retrieve version information 
	char *cpInfoBuf = new char[dwInfoSize];
	if(!cpInfoBuf)
	{
		return FALSE;
	}

	if(!GetFileVersionInfo(pPath, 0, dwInfoSize, cpInfoBuf))
	{
		delete [] cpInfoBuf;
		return FALSE;
	}   

	//Get the language setting first 
	if(!VerQueryValue(cpInfoBuf, _TEXT("\\VarFileInfo\\Translation"), (LPVOID*)&dwTranslation, &uTranslate))
	{
		delete [] cpInfoBuf;
		return FALSE;
	}

	if(*dwTranslation == NULL)
	{
		delete [] cpInfoBuf;
		return FALSE;
	}

	dwTrans = MAKELONG(HIWORD (dwTranslation[0]), LOWORD (dwTranslation[0]));
	// Read the file description for each language and code page.
	WCHAR *szpVersion[] = { const_cast<wchar_t*>(L"CompanyName"), 
        const_cast<wchar_t*>(L"FileVersion"),
        const_cast<wchar_t*>(L"LegalCopyright"),
        const_cast<wchar_t*>(L"PrivateBuild"),
        const_cast<wchar_t*>(L"Comments"),
        const_cast<wchar_t*>(L"InternalName"),
        const_cast<wchar_t*>(L"ProductName"),
        const_cast<wchar_t*>(L"ProductVersion"),
        const_cast<wchar_t*>(L"FileDescription"),
        const_cast<wchar_t*>(L"LegalTrademarks"),
        const_cast<wchar_t*>(L"OriginalFilename"),
        const_cast<wchar_t*>(L"SpecialBuild") };


	for (int i = 0 ; i < VERSIONCOUNT ; i++)
	{
		swprintf_s( cSubBlock, _TEXT("\\StringFileInfo\\%08lx\\%s"), dwTrans, szpVersion[i]); 
		if (!VerQueryValue(cpInfoBuf, cSubBlock, (LPVOID* )&cpBuffer, &uBytes))
		{
			//printf("Warning : The file is no version information.\n");
			//return FALSE;
			//m_csRCVersionInfo[i] = "";
			continue;
		}
		//m_csRCVersionInfo[i] = cpBuffer;
		//MessageBox(0,cpBuffer,0,0);
		pFileVersionStr[i] = cpBuffer;
	}  

	delete [] cpInfoBuf;
	dwTranslation = NULL;
	cpBuffer = NULL;

	return TRUE;
}
//BOOL GetFileOwner(TCHAR * pPath,wstring * pDomainName,wstring * pAcctName)
//{
//	DWORD dwRtnCode = 0;
//	PSID pSidOwner = NULL;
//	BOOL bRtnBool = TRUE;
//	LPTSTR AcctName = NULL;
//	LPTSTR DomainName = NULL;
//	DWORD dwAcctName = 1, dwDomainName = 1;
//	SID_NAME_USE eUse = SidTypeUnknown;
//	HANDLE hFile;
//	PSECURITY_DESCRIPTOR pSD = NULL;
//
//
//	// Get the handle of the file object.
//	hFile = CreateFile(
//					  pPath,
//					  GENERIC_READ,
//					  FILE_SHARE_READ,
//					  NULL,
//					  OPEN_EXISTING,
//					  FILE_ATTRIBUTE_NORMAL| FILE_FLAG_BACKUP_SEMANTICS,
//					  NULL);
//
//	// Check GetLastError for CreateFile error code.
//	if (hFile == INVALID_HANDLE_VALUE) {
//			  DWORD dwErrorCode = 0;
//
//			  dwErrorCode = GetLastError();
//			  _tprintf(TEXT("CreateFile error = %d\n"), dwErrorCode);
//			  return FALSE;
//	}
//	printf("A\n");
//
//
//	// Get the owner SID of the file.
//	dwRtnCode = GetSecurityInfo(
//					  hFile,
//					  SE_FILE_OBJECT,
//					  OWNER_SECURITY_INFORMATION,
//					  &pSidOwner,
//					  NULL,
//					  NULL,
//					  NULL,
//					  &pSD);
//
//	// Check GetLastError for GetSecurityInfo error condition.
//	if (dwRtnCode != ERROR_SUCCESS) {
//			  DWORD dwErrorCode = 0;
//
//			  dwErrorCode = GetLastError();
//			  _tprintf(TEXT("GetSecurityInfo error = %d\n"), dwErrorCode);
//			  CloseHandle(hFile);
//			  return FALSE;
//	}
//	printf("B\n");
//	// First call to LookupAccountSid to get the buffer sizes.
//	bRtnBool = LookupAccountSid(
//					  NULL,           // local computer
//					  pSidOwner,
//					  AcctName,
//					  (LPDWORD)&dwAcctName,
//					  DomainName,
//					  (LPDWORD)&dwDomainName,
//					  &eUse);
//	printf("C\n");
//	// Reallocate memory for the buffers.
//	AcctName = (LPTSTR)GlobalAlloc(
//			  GMEM_FIXED,
//			  dwAcctName);
//
//	// Check GetLastError for GlobalAlloc error condition.
//	if (AcctName == NULL) {
//			  DWORD dwErrorCode = 0;
//
//			  dwErrorCode = GetLastError();
//			  _tprintf(TEXT("GlobalAlloc error = %d\n"), dwErrorCode);
//			  LocalFree(pSD);
//			  LocalFree(pSidOwner);
//			  CloseHandle(hFile);
//			  return FALSE;
//	}
//	printf("D\n");
//    DomainName = (LPTSTR)GlobalAlloc(
//           GMEM_FIXED,
//           dwDomainName);
//
//    // Check GetLastError for GlobalAlloc error condition.
//    if (DomainName == NULL) {
//          DWORD dwErrorCode = 0;
//
//          dwErrorCode = GetLastError();
//          _tprintf(TEXT("GlobalAlloc error = %d\n"), dwErrorCode);
//		  GlobalFree(AcctName);
//		  LocalFree(pSD);
//		  LocalFree(pSidOwner);
//		  CloseHandle(hFile);
//          return FALSE;
//
//    }
//	printf("E\n");
//    // Second call to LookupAccountSid to get the account name.
//    bRtnBool = LookupAccountSid(
//          NULL,                   // name of local or remote computer
//          pSidOwner,              // security identifier
//          AcctName,               // account name buffer
//          (LPDWORD)&dwAcctName,   // size of account name buffer 
//          DomainName,             // domain name
//          (LPDWORD)&dwDomainName, // size of domain name buffer
//          &eUse);                 // SID type
//	printf("F\n");
//    // Check GetLastError for LookupAccountSid error condition.
//    if (bRtnBool == FALSE) {
//          DWORD dwErrorCode = 0;
//
//          dwErrorCode = GetLastError();
//
//          if (dwErrorCode == ERROR_NONE_MAPPED)
//              _tprintf(TEXT
//                  ("Account owner not found for specified SID.\n"));
//          else 
//              _tprintf(TEXT("Error in LookupAccountSid.\n"));
//		   GlobalFree(DomainName);
//		   GlobalFree(AcctName);
//		   LocalFree(pSD);
//		   LocalFree(pSidOwner);
//		   CloseHandle(hFile);
//          return FALSE;
//
//    } else/* if (bRtnBool == TRUE)*/ {
//		printf("G\n");
//        // Print the account name.
//        //_tprintf(TEXT("Account owner = %s %s\n"),DomainName, AcctName);
//		*pDomainName = DomainName;
//		*pAcctName = AcctName;
//		printf("H\n");
//		 GlobalFree(DomainName);
//		 printf("I\n");
//		 GlobalFree(AcctName);
//		 printf("J\n");
//		 LocalFree(pSD);
//		 //LocalFree(pSidOwner);
//		 printf("K\n");
//		 CloseHandle(hFile);
//		 printf("L\n");
//		return TRUE;
//	}
//
//}
BOOL GetFileTimeInfo(TCHAR * pFilePath,FILETIME *pCreateTime,FILETIME *pAccessTime,FILETIME *pWriteTime)
{
	BOOL ret = FALSE;
	HANDLE hf = CreateFile(pFilePath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,NULL);
	if(hf != INVALID_HANDLE_VALUE)
	{
		if(GetFileTime(hf, pCreateTime, pAccessTime, pWriteTime))
			ret = TRUE;
		CloseHandle(hf);
	}
	return ret;
}
LONGLONG GetFileSizeInfo(TCHAR * pFilePath)
{
	LONGLONG ret = 0;
	HANDLE m_File = CreateFile(pFilePath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if(m_File != INVALID_HANDLE_VALUE)
	{
		//DWORD m_Filesize = GetFileSize(m_File, NULL);
			//DWORD readsize;
		LARGE_INTEGER m_Filesize; 
		GetFileSizeEx(m_File, &m_Filesize); 
		ret = m_Filesize.QuadPart;
		CloseHandle(m_File);
	}
	return ret;
}