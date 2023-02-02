typedef struct LM_OWF_PASSWORD {
	UCHAR data[16];
} NT_OWF_PASSWORD;

typedef struct USER_SESSION_KEY {
	UCHAR data[16];
}* PUSER_SESSION_KEY;

typedef struct NETLOGON_VALIDATION_SAM_INFO4 {
	LARGE_INTEGER LogonTime;
	LARGE_INTEGER LogoffTime;
	LARGE_INTEGER KickOffTime;
	LARGE_INTEGER PasswordLastSet;
	LARGE_INTEGER PasswordCanChange;
	LARGE_INTEGER PasswordMustChange;
	UNICODE_STRING EffectiveName;
	UNICODE_STRING FullName;
	UNICODE_STRING LogonScript;
	UNICODE_STRING ProfilePath;
	UNICODE_STRING HomeDirectory;
	UNICODE_STRING HomeDirectoryDrive;
	USHORT LogonCount;
	USHORT BadPasswordCount;
	ULONG UserId;
	ULONG PrimaryGroupId;
	ULONG GroupCount;
	PGROUP_MEMBERSHIP GroupIds;
	ULONG UserFlags;
	USER_SESSION_KEY UserSessionKey;
	UNICODE_STRING LogonServer;
	UNICODE_STRING LogonDomainName;
	PSID LogonDomainId;
	UCHAR LMKey[8];
	ULONG UserAccountControl;
	ULONG SubAuthStatus;
	LARGE_INTEGER LastSuccessfulILogon;
	LARGE_INTEGER LastFailedILogon;
	ULONG FailedILogonCount;
	ULONG Reserved4;
	ULONG SidCount;
	PSID_AND_ATTRIBUTES ExtraSids;
	UNICODE_STRING DnsLogonDomainName;
	UNICODE_STRING Upn;
	UNICODE_STRING ExpansionString1;
	UNICODE_STRING ExpansionString2;
	UNICODE_STRING ExpansionString3;
	UNICODE_STRING ExpansionString4;
	UNICODE_STRING ExpansionString5;
	UNICODE_STRING ExpansionString6;
	UNICODE_STRING ExpansionString7;
	UNICODE_STRING ExpansionString8;
	UNICODE_STRING ExpansionString9;
	UNICODE_STRING ExpansionString10;
} *PNETLOGON_VALIDATION_SAM_INFO4;

typedef union NETLOGON_VALIDATION {
	PNETLOGON_VALIDATION_SAM_INFO4 ValidationSam4;
} *PNETLOGON_VALIDATION;

typedef struct NETLOGON_LOGON_IDENTITY_INFO {
	UNICODE_STRING LogonDomainName;
	ULONG ParameterControl;
	LUID  LogonId;
	UNICODE_STRING UserName;
	UNICODE_STRING Workstation;
} *PNETLOGON_LOGON_IDENTITY_INFO;

typedef struct NETLOGON_INTERACTIVE_INFO : public NETLOGON_LOGON_IDENTITY_INFO {
	LM_OWF_PASSWORD LmOwfPassword;
	NT_OWF_PASSWORD NtOwfPassword;
} *PNETLOGON_INTERACTIVE_INFO;

typedef union NETLOGON_LEVEL {
	PNETLOGON_INTERACTIVE_INFO LogonInteractive;
} *PNETLOGON_LEVEL;

typedef struct NETLOGON_CREDENTIAL {
	UCHAR data[8];
} *PNETLOGON_CREDENTIAL;

typedef struct NETLOGON_AUTHENTICATOR : public NETLOGON_CREDENTIAL {
	ULONG Timestamp;
} *PNETLOGON_AUTHENTICATOR;

enum NETLOGON_VALIDATION_INFO_CLASS
{
	NetlogonValidationUasInfo = 1,
	NetlogonValidationSamInfo,
	NetlogonValidationSamInfo2,
	NetlogonValidationGenericInfo,
	NetlogonValidationGenericInfo2,
	NetlogonValidationSamInfo4
};

enum NETLOGON_LOGON_INFO_CLASS {
	NetlogonInteractiveInformation = 1,
	NetlogonNetworkInformation,
	NetlogonServiceInformation,
	NetlogonGenericInformation,
	NetlogonInteractiveTransitiveInformation,
	NetlogonNetworkTransitiveInformation,
	NetlogonServiceTransitiveInformation
};
