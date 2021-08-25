#include "structs.h"
#include <stdio.h>
#include <shlwapi.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "Ncrypt.lib")
#pragma comment (lib, "Shlwapi.lib")

HRESULT SignCallBack(
	PCCERT_CONTEXT pCertContext,
	PVOID pvExtra,
	DWORD algId,
	BYTE* pDigestToSign,
	DWORD dwDigestToSign,
	CRYPT_DATA_BLOB* blob
);

BYTE* sign(PCCERT_CONTEXT ctx, BYTE* digest, DWORD digestSize);

typedef HRESULT(WINAPI *FuncSignerSignEx3)(
	DWORD flag,
	PSIGNER_SUBJECT_INFO pSubjectInfo,
	PSIGNER_CERT pSignerCert,
	PSIGNER_SIGNATURE_INFO pSignatureInfo,
	PVOID pProviderInfo,
	DWORD dwTimestampFlags,
	PCSTR pszTimestampAlgorithmOid,
	PCWSTR pwszHttpTimeStamp,
	PCRYPT_ATTRIBUTES psRequest,
	PVOID pSipData,
	SIGNER_CONTEXT **ppSignerContext,
	HANDLE pCryptoPolicy,
	PSIGN_CALLBACK_INFO pSignInfo,
	PVOID pReserved
	);

PCCERT_CONTEXT gCertCtx = NULL;
LPCWSTR fileToSign = L"C:\\Users\\rango\\Downloads\\RDCNotificationClient.appx";
LPCSTR signingCertSubject = "Adobe Systems Incorporated";

PCCERT_CONTEXT get_signer_cert() {
	HCERTSTORE hSysStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
	if (hSysStore == NULL) {
		return NULL;
	}

	LPCSTR subject = signingCertSubject;
	PCCERT_CONTEXT certCtx = CertFindCertificateInStore(hSysStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR_A, subject, NULL);
	if (NULL == certCtx) {
		return NULL;
	}

	return certCtx;
}

HCERTSTORE create_signer_cert_store(PCCERT_CONTEXT certctx) {
	HCERTSTORE memstore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, NULL);
	if (memstore == NULL) {
		return NULL;
	}

	return CertAddCertificateContextToStore(memstore, certctx, CERT_STORE_ADD_NEW, 0) ? memstore : NULL;
}

int main(int argc, char* argv) {

	/* 1 SIGNER_SUBJECT_INFO */
	SIGNER_FILE_INFO signerFileInfo;
	signerFileInfo.cbSize = sizeof(SIGNER_FILE_INFO);
	//signerFileInfo.pwszFileName = L"C:\\Users\\rango\\Downloads\\iii.exe";
	signerFileInfo.pwszFileName = fileToSign;
	signerFileInfo.hFile = NULL;

	SIGNER_SUBJECT_INFO signerSubjectInfo;
	DWORD index = 0;
	signerSubjectInfo.cbSize = sizeof(SIGNER_SUBJECT_INFO);
	signerSubjectInfo.pdwIndex = &index;
	signerSubjectInfo.dwSubjectChoice = 0x1; //  SIGNER_SUBJECT_FILE;
	signerSubjectInfo.pSignerFileInfo = &signerFileInfo;

	/* 2 SIGNER_CERT */
	gCertCtx = get_signer_cert();
	if (NULL == gCertCtx)
		return 1;
	SIGNER_CERT_STORE_INFO certStoreInfo;
	certStoreInfo.cbSize = sizeof(SIGNER_CERT_STORE_INFO);
	certStoreInfo.dwCertPolicy = 1; // SIGNER_CERT_POLICY_STORE
	certStoreInfo.pSigningCert = gCertCtx;
	certStoreInfo.hCertStore = create_signer_cert_store(gCertCtx);

	SIGNER_CERT signerCert;
	signerCert.cbSize = sizeof(SIGNER_CERT);
	signerCert.dwCertChoice = 2; // SIGNER_CERT_STORE
	signerCert.pCertStoreInfo = &certStoreInfo;
	signerCert.hwnd = NULL;

	/* 3 SIGNER_SIGNATURE_INFO */
	SIGNER_ATTR_AUTHCODE signerAttr;
	signerAttr.cbSize = sizeof(SIGNER_ATTR_AUTHCODE);
	signerAttr.fCommercial = 0;
	signerAttr.fIndividual = 0;
	signerAttr.pwszName = L"trustasia";
	signerAttr.pwszInfo = L"www.trustasia.com";

	SIGNER_SIGNATURE_INFO signatureInfo;
	signatureInfo.algidHash = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256;
	signatureInfo.cbSize = sizeof(SIGNER_SIGNATURE_INFO);
	signatureInfo.dwAttrChoice = 1; // SIGNER_AUTHCODE_ATTR
	signatureInfo.pAttrAuthcode = &signerAttr;
	signatureInfo.psAuthenticated = 0;
	signatureInfo.psUnauthenticated = 0;

	/* 4 SIGN_CALLBACK_INFO */
	SIGN_CALLBACK_INFO callback;
	callback.cbSize = sizeof(SIGN_CALLBACK_INFO);
	callback.callback = SignCallBack;
	callback.pvOpaque = NULL;

	/* 5 TIMESTAMP */
	
	/* 6 APPX_SIP_CLIENT_DATA OPT */
	DWORD tsFlag = 0; // SIGNER_TIMESTAMP_AUTHENTICODE:1 & SIGNER_TIMESTAMP_RFC3161: 2
	LPCWSTR tsURL = NULL;
	LPCSTR tsOID = NULL;
	DWORD flags = (DWORD)SIGN_CALLBACK_UNDOCUMENTED;
	PVOID pSipData = NULL;
	SIGNER_CONTEXT* context = NULL;
	LPCWSTR ext = PathFindExtensionW(signerFileInfo.pwszFileName);
	if (StrCmpW(ext, L".msix")==0 || StrCmpW(ext, L".appx") == 0) {
		flags = (DWORD)(SIGN_CALLBACK_UNDOCUMENTED | SPC_EXC_PE_PAGE_HASHES_FLAG);

		SIGNER_SIGN_EX3_PARAMS parameters;
		parameters.pCryptoPolicy = NULL;
		parameters.pProviderInfo = NULL;
		parameters.pReserved = NULL;
		parameters.psRequest = NULL;
		parameters.dwFlags = flags;
		parameters.dwTimestampFlags = tsFlag;
		parameters.ppSignerContext = &context;
		parameters.pSignatureInfo = &signatureInfo;
		parameters.pSigningCert = &signerCert;
		parameters.signCallbackInfo = &callback;
		parameters.pSubjectInfo = &signerSubjectInfo;
		parameters.pwszTimestampURL = tsURL;
		parameters.pszTimestampAlgorithmOid = tsOID;

		APPX_SIP_CLIENT_DATA clientData;
		clientData.pSignerParams = &parameters;
		clientData.pAppxSipState = NULL;

		pSipData = &clientData;
	}
	


	HMODULE hMssign32 = LoadLibrary("mssign32.dll");
	if (hMssign32 == NULL) {
		return 1;
	}

	FuncSignerSignEx3 signerSignEx3 = (FuncSignerSignEx3)GetProcAddress(hMssign32, "SignerSignEx3");
	if (signerSignEx3 == NULL) {
		return 2;
	}

	HRESULT hRes = signerSignEx3(
		flags,
		&signerSubjectInfo,
		&signerCert,
		&signatureInfo,
		NULL,
		tsFlag,
		tsOID,
		tsURL,
		NULL,
		pSipData,
		&context,
		NULL,
		&callback,
		NULL
	);

	if (!SUCCEEDED(hRes)) {
		DWORD errcode = GetLastError();
		printf("failed code: %d\n", errcode);
		return 1;
	}

	printf("success\n");
	return 0;
}

HRESULT SignCallBack(
	PCCERT_CONTEXT pCertContext,
	PVOID pvExtra,
	DWORD algId,
	BYTE* pDigestToSign,
	DWORD dwDigestToSign,
	CRYPT_DATA_BLOB* blob
) {

	BYTE* sig = sign(gCertCtx, pDigestToSign, dwDigestToSign);
	if (NULL == sig) {
		return 1;
	}

	BYTE* sigCopy = (BYTE*)LocalAlloc(0x0000, 256); // Notice!
	if (NULL == sigCopy)
		return 1;

	memcpy(sigCopy, sig, 256);
	blob->cbData = 256;
	blob->pbData = sigCopy;
	return 0;
}


BYTE* sign(PCCERT_CONTEXT ctx, BYTE* digest, DWORD digestSize)
{
	/* CSP 容器信息 */
	DWORD cbSize = 0;
	BOOL bRet = CertGetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cbSize);
	if (!bRet) {
		return NULL;
	}

	PCRYPT_KEY_PROV_INFO provider = (PCRYPT_KEY_PROV_INFO)malloc(cbSize);
	if (NULL == provider) {
		return NULL;
	}
	bRet = CertGetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, provider, &cbSize);
	if (!bRet) {
		return NULL;
	}

	/* 私钥对象 */
	NCRYPT_PROV_HANDLE hProv = NULL;
	SECURITY_STATUS status = NCryptOpenStorageProvider(&hProv, provider->pwszProvName, 0);
	if (ERROR_SUCCESS != status) {
		//goto error;
		return NULL;
	}

	NCRYPT_KEY_HANDLE hKey = NULL;
	status = NCryptOpenKey(hProv, &hKey, provider->pwszContainerName, 0, 0);
	if (ERROR_SUCCESS != status) {
		//goto error;
		return NULL;
	}

	/* 开始签名 */
	BCRYPT_PKCS1_PADDING_INFO paddingInfo;
	paddingInfo.pszAlgId = L"SHA256";
	
	DWORD cbSig = 0;
	status = NCryptSignHash(hKey, &paddingInfo, digest, digestSize, NULL, 0, &cbSig, NCRYPT_PAD_PKCS1_FLAG);
	if (ERROR_SUCCESS != status) {
		//goto error;
		return NULL;
	}

	BYTE* sig = (BYTE*)malloc(cbSig);
	status = NCryptSignHash(hKey, &paddingInfo, digest, digestSize, sig, cbSig, &cbSig, NCRYPT_PAD_PKCS1_FLAG);
	if (ERROR_SUCCESS != status) {
		//goto error;
		return NULL;
	}

	if (NULL != hKey)
		NCryptFreeObject(hKey);

	return sig;
}