#pragma once


#include <stdio.h>
#include <tchar.h>
#include <windows.h> 

#include <ntsecapi.h>

#define SAM_HANDLE HANDLE
#define PSAM_HANDLE PHANDLE
#define SAM_SERVER_CONNECT   0x00000001
#define SAM_SERVER_LOOKUP_DOMAIN   0x00000020

#define DOMAIN_CREATE_USER   0x00000010
#define DOMAIN_LOOKUP   0x00000200
#define DOMAIN_READ_PASSWORD_PARAMETERS   0x00000001


#define USER_NORMAL_ACCOUNT   0x00000010
#define USER_READ_GENERAL   0x00000001
#define USER_READ_PREFERENCES   0x00000002
#define USER_WRITE_PREFERENCES   0x00000004
#define USER_READ_LOGON   0x00000008
#define USER_READ_ACCOUNT   0x00000010
#define USER_WRITE_ACCOUNT   0x00000020
#define USER_CHANGE_PASSWORD   0x00000040
#define USER_FORCE_PASSWORD_CHANGE   0x00000080
#define USER_LIST_GROUPS   0x00000100
#define USER_READ_GROUP_INFORMATION   0x00000200
#define USER_WRITE_GROUP_INFORMATION   0x00000400

#define USER_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED |\
                                        USER_READ_GENERAL |\
                                        USER_READ_PREFERENCES |\
                                        USER_WRITE_PREFERENCES |\
                                        USER_READ_LOGON |\
                                        USER_READ_ACCOUNT |\
                                        USER_WRITE_ACCOUNT |\
                                        USER_CHANGE_PASSWORD |\
                                        USER_FORCE_PASSWORD_CHANGE |\
                                        USER_LIST_GROUPS |\
                                        USER_READ_GROUP_INFORMATION |\
                                        USER_WRITE_GROUP_INFORMATION)

#define USER_ALL_NTPASSWORDPRESENT   0x01000000
#define USER_ALL_HOMEDIRECTORY   0x00000040
#define USER_ALL_ADMINCOMMENT   0x00000010
#define USER_ALL_USERACCOUNTCONTROL   0x00100000
#define USER_ALL_SCRIPTPATH   0x00000100

typedef enum _USER_INFORMATION_CLASS {
	UserGeneralInformation = 1,
	UserPreferencesInformation,
	UserLogonInformation,
	UserLogonHoursInformation,
	UserAccountInformation,
	UserNameInformation,
	UserAccountNameInformation,
	UserFullNameInformation,
	UserPrimaryGroupInformation,
	UserHomeInformation,
	UserScriptInformation,
	UserProfileInformation,
	UserAdminCommentInformation,
	UserWorkStationsInformation,
	UserSetPasswordInformation,
	UserControlInformation,
	UserExpiresInformation,
	UserInternal1Information,
	UserInternal2Information,
	UserParametersInformation,
	UserAllInformation,
	UserInternal3Information,
	UserInternal4Information,
	UserInternal5Information,
	UserInternal4InformationNew,
	UserInternal5InformationNew,
	UserInternal6Information,
	UserExtendedInformation,
	UserLogonUIInformation,
}USER_INFORMATION_CLASS, * PUSER_INFORMATION_CLASS;

typedef struct _SR_SECURITY_DESCRIPTOR
{
	ULONG Length;
	PUCHAR SecurityDescriptor;
} SR_SECURITY_DESCRIPTOR, * PSR_SECURITY_DESCRIPTOR;

typedef struct _LOGON_HOURS
{
	USHORT UnitsPerWeek;
	PUCHAR LogonHours;
} LOGON_HOURS, * PLOGON_HOURS;

typedef struct _USER_ALL_INFORMATION
{
	LARGE_INTEGER LastLogon;
	LARGE_INTEGER LastLogoff;
	LARGE_INTEGER PasswordLastSet;
	LARGE_INTEGER AccountExpires;
	LARGE_INTEGER PasswordCanChange;
	LARGE_INTEGER PasswordMustChange;
	UNICODE_STRING UserName;
	UNICODE_STRING FullName;
	UNICODE_STRING HomeDirectory;
	UNICODE_STRING HomeDirectoryDrive;
	UNICODE_STRING ScriptPath;
	UNICODE_STRING ProfilePath;
	UNICODE_STRING AdminComment;
	UNICODE_STRING WorkStations;
	UNICODE_STRING UserComment;
	UNICODE_STRING Parameters;
	UNICODE_STRING LmPassword;
	UNICODE_STRING NtPassword;
	UNICODE_STRING PrivateData;
	SR_SECURITY_DESCRIPTOR SecurityDescriptor;
	ULONG UserId;
	ULONG PrimaryGroupId;
	ULONG UserAccountControl;
	ULONG WhichFields;
	LOGON_HOURS LogonHours;
	USHORT BadPasswordCount;
	USHORT LogonCount;
	USHORT CountryCode;
	USHORT CodePage;
	BOOLEAN LmPasswordPresent;
	BOOLEAN NtPasswordPresent;
	BOOLEAN PasswordExpired;
	BOOLEAN PrivateDataSensitive;
} USER_ALL_INFORMATION, * PUSER_ALL_INFORMATION;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;



typedef NTSTATUS(NTAPI* pSamConnect)(PUNICODE_STRING,
	SAM_HANDLE,
	ACCESS_MASK,
	POBJECT_ATTRIBUTES
	);

typedef NTSTATUS(NTAPI* pSamOpenDomain)(IN SAM_HANDLE 	ServerHandle,
	IN ACCESS_MASK 	DesiredAccess,
	IN PSID 	DomainId,
	OUT PSAM_HANDLE 	DomainHandle
	);


typedef NTSTATUS(NTAPI* pSamCreateUser2InDomain)(IN SAM_HANDLE 	DomainHandle,
	IN PUNICODE_STRING 	AccountName,
	IN ULONG 	AccountType,
	IN ACCESS_MASK 	DesiredAccess,
	OUT PSAM_HANDLE 	UserHandle,
	OUT PULONG 	GrantedAccess,
	OUT PULONG 	RelativeId
	);


typedef ULONG_PTR(NTAPI* pSetUserInfo)(SAM_HANDLE 	UserHandle,
	LPBYTE 	UserInfo,
	DWORD 	Level,
	PDWORD 	parm_err
	);

typedef NTSTATUS(*pGetAccountDomainSid)(IN PUNICODE_STRING 	ServerName,
	OUT PSID* AccountDomainSid
	);

typedef void (*pRtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR          SourceString
	);

typedef NTSTATUS(NTAPI* pSamSetInformationUser)(SAM_HANDLE 	UserHandle,
	USER_INFORMATION_CLASS UserInformationClass,
	PVOID 	Buffer
	);

typedef NTSTATUS(NTAPI* pSamQuerySecurityObject)(IN SAM_HANDLE 	ObjectHandle,
	IN SECURITY_INFORMATION 	SecurityInformation,
	OUT PSECURITY_DESCRIPTOR* SecurityDescriptor
	);
typedef NTSYSAPI NTSTATUS(NTAPI* pRtlGetDaclSecurityDescriptor)(_In_ PSECURITY_DESCRIPTOR 	SecurityDescriptor,
	_Out_ PBOOLEAN 	DaclPresent,
	_Out_ PACL* Dacl,
	_Out_ PBOOLEAN 	DaclDefaulted
	);

typedef NTSYSAPI NTSTATUS(WINAPI* pRtlQueryInformationAcl)(PACL,
	LPVOID,
	DWORD,
	ACL_INFORMATION_CLASS
	);