#pragma once
#include <Windows.h>


typedef struct _SIGNER_BLOB_INFO {
    DWORD cbSize;
    GUID* pGuidSubject;
    DWORD cbBlob;
    BYTE* pbBlob;
    LPCWSTR pwszDisplayName;
} SIGNER_BLOB_INFO, * PSIGNER_BLOB_INFO;

typedef struct _SIGNER_FILE_INFO {
    DWORD  cbSize;
    LPCWSTR pwszFileName;
    HANDLE hFile;
} SIGNER_FILE_INFO, * PSIGNER_FILE_INFO;

typedef struct _SIGNER_SUBJECT_INFO {
    DWORD cbSize;
    DWORD* pdwIndex;
    DWORD dwSubjectChoice;
    union {
        SIGNER_FILE_INFO* pSignerFileInfo;
        SIGNER_BLOB_INFO* pSignerBlobInfo;
    };
} SIGNER_SUBJECT_INFO, * PSIGNER_SUBJECT_INFO;

typedef struct _SIGNER_CERT_STORE_INFO {
    DWORD cbSize;
    PCCERT_CONTEXT pSigningCert;
    DWORD dwCertPolicy;
    HCERTSTORE hCertStore;
} SIGNER_CERT_STORE_INFO, * PSIGNER_CERT_STORE_INFO;

typedef struct _SIGNER_SPC_CHAIN_INFO {
    DWORD cbSize;
    LPCWSTR pwszSpcFile;
    DWORD dwCertPolicy;
    HCERTSTORE hCertStore;
} SIGNER_SPC_CHAIN_INFO, * PSIGNER_SPC_CHAIN_INFO;

typedef struct _SIGNER_CERT {
    DWORD cbSize;
    DWORD dwCertChoice;
    union {
        LPCWSTR pwszSpcFile;
        SIGNER_CERT_STORE_INFO* pCertStoreInfo;
        SIGNER_SPC_CHAIN_INFO* pSpcChainInfo;
    };
    HWND hwnd;
} SIGNER_CERT, * PSIGNER_CERT;

typedef struct _SIGNER_ATTR_AUTHCODE {
    DWORD cbSize;
    BOOL fCommercial;
    BOOL fIndividual;
    LPCWSTR pwszName;
    LPCWSTR pwszInfo;
} SIGNER_ATTR_AUTHCODE, * PSIGNER_ATTR_AUTHCODE;

typedef struct _SIGNER_SIGNATURE_INFO {
    DWORD cbSize;
    ALG_ID algidHash;
    DWORD dwAttrChoice;
    union {
        SIGNER_ATTR_AUTHCODE* pAttrAuthcode;
    };
    PCRYPT_ATTRIBUTES psAuthenticated;
    PCRYPT_ATTRIBUTES psUnauthenticated;
} SIGNER_SIGNATURE_INFO, * PSIGNER_SIGNATURE_INFO;

typedef struct _SIGN_CALLBACK_INFO
{
    DWORD cbSize;
    HANDLE callback;
    HANDLE pvOpaque;
} SIGN_CALLBACK_INFO, * PSIGN_CALLBACK_INFO;


typedef struct _SIGNER_CONTEXT {
    DWORD cbSize;
    DWORD cbBlob;
    BYTE* pbBlob;
} SIGNER_CONTEXT, * PSIGNER_CONTEXT;

enum SignerSignEx3Flags
{
    NONE = 0x0,
    SPC_EXC_PE_PAGE_HASHES_FLAG = 0x010,
    SPC_INC_PE_IMPORT_ADDR_TABLE_FLAG = 0x020,
    SPC_INC_PE_DEBUG_INFO_FLAG = 0x040,
    SPC_INC_PE_RESOURCES_FLAG = 0x080,
    SPC_INC_PE_PAGE_HASHES_FLAG = 0x0100,
    SIGN_CALLBACK_UNDOCUMENTED = 0x0400,
    SIG_APPEND = 0x1000
};

//typedef struct _SIGNER_SIGN_EX3_PARAMS {
//    SignerSignEx3Flags flag;
//    PSIGNER_SUBJECT_INFO pSubjectInfo;
//    PSIGNER_CERT pSignerCert;
//    PSIGNER_SIGNATURE_INFO pSignatureInfo;
//    PVOID pProviderInfo ;
//    DWORD dwTimestampFlags;
//    PCSTR pszTimestampAlgorithmOid;
//    PCWSTR pwszHttpTimeStamp;
//    PCRYPT_ATTRIBUTES psRequest;
//    SIGNER_CONTEXT** ppSignerContext;
//    HANDLE pCryptoPolicy;
//    PSIGN_CALLBACK_INFO pSignInfo;
//    PVOID pReserved;
//} SIGNER_SIGN_EX3_PARAMS;

typedef struct _SIGNER_PROVIDER_INFO {
    DWORD cbSize;
    LPCWSTR pwszProviderName;
    DWORD dwProviderType;
    DWORD dwKeySpec;
    DWORD dwPvkChoice;
    union {
        LPWSTR pwszPvkFileName;
        LPWSTR pwszKeyContainer;
    };
} SIGNER_PROVIDER_INFO, * PSIGNER_PROVIDER_INFO;

typedef struct _SIGNER_SIGN_EX3_PARAMS{
    DWORD dwFlags;
    SIGNER_SUBJECT_INFO* pSubjectInfo;
    SIGNER_CERT* pSigningCert;
    SIGNER_SIGNATURE_INFO* pSignatureInfo;
    SIGNER_PROVIDER_INFO* pProviderInfo;
    DWORD dwTimestampFlags;
    PCSTR pszTimestampAlgorithmOid;
    PCWSTR pwszTimestampURL;
    CRYPT_ATTRIBUTES* psRequest;
    PSIGN_CALLBACK_INFO signCallbackInfo;
    SIGNER_CONTEXT** ppSignerContext;
    CERT_STRONG_SIGN_PARA* pCryptoPolicy;
    PVOID pReserved;
} SIGNER_SIGN_EX3_PARAMS;


typedef struct _APPX_SIP_CLIENT_DATA {
    SIGNER_SIGN_EX3_PARAMS* pSignerParams;
    PVOID pAppxSipState;
} APPX_SIP_CLIENT_DATA;

