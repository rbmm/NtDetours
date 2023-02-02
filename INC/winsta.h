#pragma once 
// [MS-TSTS] specific defines
  
 #define WDPREFIX_LENGTH           12
 #define STACK_ADDRESS_LENGTH     128
 #define MAX_BR_NAME               65
 #define DIRECTORY_LENGTH         256
 #define INITIALPROGRAM_LENGTH    256
 #define USERNAME_LENGTH           20
 #define DOMAIN_LENGTH             17
 #define PASSWORD_LENGTH           14
 #define NASISPECIFICNAME_LENGTH   14
 #define NASIUSERNAME_LENGTH       47
 #define NASIPASSWORD_LENGTH       24
 #define NASISESSIONNAME_LENGTH    16
 #define NASIFILESERVER_LENGTH     47
  
 #define CLIENTDATANAME_LENGTH      7
 #define CLIENTNAME_LENGTH         20
 #define CLIENTADDRESS_LENGTH      30
 #define IMEFILENAME_LENGTH        32
 #define DIRECTORY_LENGTH         256
 #define CLIENTLICENSE_LENGTH      32
 #define CLIENTMODEM_LENGTH        40
 #define CLIENT_PRODUCT_ID_LENGTH  32
 #define MAX_COUNTER_EXTENSIONS     2    
 #define WINSTATIONNAME_LENGTH     32
  
  
 typedef enum _SDCLASS {
     SdNone = 0,
     SdConsole,
     SdNetwork,
     SdAsync,
     SdOemTransport
 } SDCLASS;
  
 typedef enum _FLOWCONTROLCLASS {
     FlowControl_None,
     FlowControl_Hardware,
     FlowControl_Software
 } FLOWCONTROLCLASS;
  
 typedef enum _WINSTATIONSTATECLASS {
     State_Active = 0,
     State_Connected = 1,
     State_ConnectQuery = 2,
     State_Shadow = 3,
     State_Disconnected = 4,
     State_Idle = 5,
     State_Listen = 6,
     State_Reset = 7,
     State_Down = 8,
     State_Init = 9
 } WINSTATIONSTATECLASS;
  
 typedef WCHAR   NASISPECIFICNAME[ NASISPECIFICNAME_LENGTH + 1 ];
  
 typedef WCHAR   NASIUSERNAME[ NASIUSERNAME_LENGTH + 1 ];
  
 typedef WCHAR   NASIPASSWORD[ NASIPASSWORD_LENGTH + 1 ];
  
 typedef WCHAR   NASISESIONNAME[ NASISESSIONNAME_LENGTH + 1 ];
  
 typedef WCHAR   NASIFILESERVER[ NASIFILESERVER_LENGTH + 1 ];
  
 typedef CHAR CLIENTDATANAME[ CLIENTDATANAME_LENGTH + 1 ];
 typedef CHAR * PCLIENTDATANAME;
  
 typedef WCHAR WINSTATIONNAME[ WINSTATIONNAME_LENGTH + 1 ];
  
 typedef struct _TS_SYSTEMTIME {
     USHORT wYear;
     USHORT wMonth;
     USHORT wDayOfWeek;
     USHORT wDay;
     USHORT wHour;
     USHORT wMinute;
     USHORT wSecond;
     USHORT wMilliseconds;
 } TS_SYSTEMTIME;
  
 typedef struct _TS_TIME_ZONE_INFORMATION {
     LONG Bias;
     WCHAR StandardName[32 ];
     TS_SYSTEMTIME StandardDate;
     LONG StandardBias;
     WCHAR DaylightName[32 ];
     TS_SYSTEMTIME DaylightDate;
     LONG DaylightBias;
 } TS_TIME_ZONE_INFORMATION;
  
  
 #ifdef _WIN64
 typedef unsigned __int64 ULONG_PTR;
 #else
 typedef ULONG ULONG_PTR;
 #endif
  
 typedef  ULONG  PTR_SIZE_T;
  
 typedef enum {
     SF_SERVICES_SESSION_POPUP
 } SESSION_FILTER;
  
 #define PROTOCOL_CONSOLE         0    
 #define PROTOCOL_ICA             1    
 #define PROTOCOL_TSHARE          2    
 #define PROTOCOL_RDP             2    
 #define PDNAME_LENGTH            32
 #define WDNAME_LENGTH            32
 #define CDNAME_LENGTH            32
 #define DEVICENAME_LENGTH        128
 #define MODEMNAME_LENGTH         DEVICENAME_LENGTH
 #define CALLBACK_LENGTH          50
 #define DLLNAME_LENGTH           32
 #define WINSTATIONCOMMENT_LENGTH 60
 #define MAX_LICENSE_SERVER_LENGTH 1024
 #define LOGONID_CURRENT     ((ULONG)-1)
 #define MAX_PDCONFIG             10  
  
 #define TERMSRV_TOTAL_SESSIONS     1     
 #define TERMSRV_DISC_SESSIONS      2     
 #define TERMSRV_RECON_SESSIONS     3     
 #define TERMSRV_CURRENT_ACTIVE_SESSIONS 4   
 #define TERMSRV_CURRENT_DISC_SESSIONS   5   
 #define TERMSRV_PENDING_SESSIONS        6   
 #define TERMSRV_SUCC_TOTAL_LOGONS       7   
 #define TERMSRV_SUCC_LOCAL_LOGONS       8   
 #define TERMSRV_SUCC_REMOTE_LOGONS      9   
 #define TERMSRV_SUCC_SESSION0_LOGONS   10   
 #define TERMSRV_CURRENT_TERMINATING_SESSIONS  11
 #define TERMSRV_CURRENT_LOGGEDON_SESSIONS     12
  
 #define NO_FALLBACK_DRIVERS  0x0  
 #define FALLBACK_BESTGUESS   0x1
 #define FALLBACK_PCL         0x2
 #define FALLBACK_PS          0x3
 #define FALLBACK_PCLANDPS    0x4
  
 /*********************************
 *   WinStationOpen access values
 *********************************/
  
 #define WINSTATION_QUERY        0x00000001  /* WinStationQueryInformation() */
 #define WINSTATION_SET          0x00000002  /* WinStationSetInformation()   */
 #define WINSTATION_RESET        0x00000004  /* WinStationReset()            */
 #define WINSTATION_VIRTUAL      0x00000008  /* read/write direct data       */
 #define WINSTATION_SHADOW       0x00000010  /* WinStationShadow()           */
 #define WINSTATION_LOGON        0x00000020  /* logon to WinStation          */
 #define WINSTATION_LOGOFF       0x00000040  /* WinStationLogoff()           */
 #define WINSTATION_MSG          0x00000080  /* WinStationMsg()              */
 #define WINSTATION_CONNECT      0x00000100  /* WinStationConnect()          */
 #define WINSTATION_DISCONNECT   0x00000200  /* WinStationDisconnect()       */
 #define WINSTATION_GUEST_ACCESS (WINSTATION_LOGON)
 #define WINSTATION_CURRENT_GUEST_ACCESS (WINSTATION_VIRTUAL | \
     WINSTATION_LOGOFF)
 #define WINSTATION_USER_ACCESS (WINSTATION_GUEST_ACCESS |    \
     WINSTATION_QUERY |           \
     WINSTATION_CONNECT )
 #define WINSTATION_CURRENT_USER_ACCESS (WINSTATION_SET |     \
     WINSTATION_RESET |   \
     WINSTATION_VIRTUAL | \
     WINSTATION_LOGOFF |  \
     WINSTATION_DISCONNECT)
 #define WINSTATION_ALL_ACCESS ( STANDARD_RIGHTS_REQUIRED |   \
     WINSTATION_QUERY |           \
     WINSTATION_SET |             \
     WINSTATION_RESET |           \
     WINSTATION_VIRTUAL |         \
     WINSTATION_SHADOW |          \
     WINSTATION_LOGON |           \
     WINSTATION_MSG |             \
     WINSTATION_CONNECT |         \
     WINSTATION_DISCONNECT)
  
 typedef WCHAR PDNAME[ PDNAME_LENGTH + 1 ];
 typedef WCHAR * PPDNAME;
  
 /*------------------------------------------------*/
  
 typedef WCHAR WDNAME[ WDNAME_LENGTH + 1 ];
 typedef WCHAR * PWDNAME;
  
 /*------------------------------------------------*/
  
 typedef WCHAR CDNAME[ CDNAME_LENGTH + 1 ];
 typedef WCHAR * PCDNAME;
  
 /*------------------------------------------------*/
  
 typedef WCHAR DEVICENAME[ DEVICENAME_LENGTH + 1 ];
 typedef WCHAR * PDEVICENAME;
  
 /*------------------------------------------------*/
  
 typedef WCHAR MODEMNAME[ MODEMNAME_LENGTH + 1 ];
 typedef WCHAR * PMODEMNAME;
  
 /*------------------------------------------------*/
  
 typedef WCHAR DLLNAME[ DLLNAME_LENGTH + 1 ];
 typedef WCHAR * PDLLNAME;
 typedef CHAR DLLNAMEA[ DLLNAME_LENGTH + 1 ];
  
 /*------------------------------------------------*/
  
 typedef WCHAR WDPREFIX[ WDPREFIX_LENGTH + 1 ];
 typedef WCHAR * PWDPREFIX;
  
 /*
 *  Stack address structure
 */
  
 typedef struct _CLIENT_STACK_ADDRESS {
     BYTE Address[ STACK_ADDRESS_LENGTH ];   // bytes 0,1 family, 2-n address
 } CLIENT_STACK_ADDRESS, *PCLIENT_STACK_ADDRESS;
  
 typedef struct _TS_TRACE {
     WCHAR TraceFile[256];
     BOOLEAN fDebugger;
     BOOLEAN fTimestamp;
     ULONG TraceClass;
     ULONG TraceEnable;
     WCHAR TraceOption[64];
 } TS_TRACE, * PTS_TRACE;
  
 #define EXTENDED_USERNAME_LEN 255
 #define EXTENDED_PASSWORD_LEN 255
 #define EXTENDED_DOMAIN_LEN 255
  
 typedef struct _ExtendedClientCredentials {
     WCHAR UserName[EXTENDED_USERNAME_LEN + 1];
     WCHAR Password[EXTENDED_PASSWORD_LEN + 1];
     WCHAR Domain[EXTENDED_DOMAIN_LEN + 1] ;
 }ExtendedClientCredentials, *pExtendedClientCredentials;
  
 /*********************************
 *  User Configuration structures
 *********************************/
  
 typedef WCHAR APPLICATIONNAME[ MAX_BR_NAME ];
 typedef WCHAR *PAPPLICATIONNAME;
  
 /*
 *  Shadow options
 */
  
 typedef enum _SHADOWCLASS {
     Shadow_Disable,
     Shadow_EnableInputNotify,
     Shadow_EnableInputNoNotify,
     Shadow_EnableNoInputNotify,
     Shadow_EnableNoInputNoNotify,
 } SHADOWCLASS;
  
 /*
 *  Callback options
 */
  
 typedef enum _CALLBACKCLASS {
     Callback_Disable,
     Callback_Roving,
     Callback_Fixed,
 } CALLBACKCLASS;
  
 typedef struct _POLICY_TS_MACHINE
 {
     ULONG   fPolicyDisableClip : 1 ;         
     ULONG   fPolicyDisableCam : 1 ;                        
     ULONG   fPolicyDisableCcm : 1 ;
     ULONG   fPolicyDisableLPT : 1;
     ULONG   fPolicyDisableCpm : 1;
     ULONG   fPolicyPromptForPassword : 1 ;
     ULONG   fPolicyMaxInstanceCount : 1;
     ULONG   fPolicyMinEncryptionLevel : 1 ;
     ULONG   fPolicyFipsEnabled : 1;
     ULONG   fPolicyDisableAutoReconnect : 1;
     ULONG   fPolicyWFProfilePath: 1 ;
     ULONG   fPolicyWFHomeDir: 1 ;
     ULONG   fPolicyWFHomeDirDrive: 1 ;
     ULONG   fPolicyDenyTSConnections      : 1;
     ULONG   fPolicyTempFoldersPerSession  : 1;
     ULONG   fPolicyDeleteTempFoldersOnExit: 1;
     ULONG   fPolicyColorDepth  : 1;
     ULONG   fPolicySessionDirectoryActive  : 1;
     ULONG   fPolicySessionDirectoryLocation  : 1;
     ULONG   fPolicySessionDirectoryClusterName  : 1;
     ULONG   fPolicySessionDirectoryAdditionalParams  : 1;
     ULONG   fPolicySessionDirectoryExposeServerIP  : 1;
     ULONG   fPolicyPreventLicenseUpgrade  : 1;
     ULONG   fPolicySecureLicensing : 1;
     ULONG   fPolicyWritableTSCCPermissionsTAB : 1;
     ULONG   fPolicyDisableCdm : 1;
     ULONG   fPolicyForceClientLptDef : 1;
     ULONG   fPolicyShadow : 1 ;                  
     ULONG   fPolicyResetBroken : 1 ;             
     ULONG   fPolicyReconnectSame : 1 ;          
     ULONG   fPolicyMaxSessionTime : 1 ;          
     ULONG   fPolicyMaxDisconnectionTime:1;       
     ULONG   fPolicyMaxIdleTime : 1 ;             
     ULONG   fPolicyInitialProgram : 1 ;         
     ULONG   fPolicySingleSessionPerUser : 1;
     ULONG   fPolicyDisableWallpaper : 1;
     ULONG   fPolicyKeepAlive   : 1;
     ULONG   fPolicyEnableTimeZoneRedirection : 1;
     ULONG   fPolicyDisableForcibleLogoff : 1;
     ULONG   fPolicyLicensingMode : 1;
     ULONG   fPolicyExplicitLSDiscovery: 1;
     ULONG   fPolicyDisableTerminalServerTooltip:1;
     ULONG   fDisableClip : 1 ;         
     ULONG   fDisableCam : 1 ;                        
     ULONG   fDisableCcm : 1 ;
     ULONG   fDisableLPT : 1;
     ULONG   fDisableCpm : 1;
     ULONG   fPromptForPassword : 1 ;
     ULONG   ColorDepth : 3;
     ULONG   fDenyTSConnections      : 1;     
     ULONG   fTempFoldersPerSession  : 1;     
     ULONG   fDeleteTempFoldersOnExit: 1;     
     ULONG   fWritableTSCCPermissionsTAB : 1; 
     ULONG   fDisableCdm  : 1;
     ULONG   fForceClientLptDef : 1;
     ULONG   fResetBroken : 1 ;             
     ULONG   fReconnectSame : 1 ;          
     ULONG   fSingleSessionPerUser:1;
     ULONG   fDisableWallpaper : 1;
     ULONG   fKeepAliveEnable : 1;
     ULONG   fPreventLicenseUpgrade:1;
     ULONG   fSecureLicensing:1;
     ULONG   fEnableTimeZoneRedirection : 1;
     ULONG   fDisableAutoReconnect : 1;
     ULONG   fDisableForcibleLogoff : 1;
     ULONG   fPolicyEncryptRPCTraffic : 1;
     ULONG   fEncryptRPCTraffic : 1;
     ULONG   fErrorInvalidProfile : 1;
     ULONG   fPolicyFallbackPrintDriver : 1;
     ULONG   FallbackPrintDriverType : 3;
     ULONG   fDisableTerminalServerTooltip : 1;
     BYTE    bSecurityLayer;
     ULONG   fPolicySecurityLayer : 1;
     BYTE    bUserAuthentication;
     ULONG   fPolicyUserAuthentication : 1;
     ULONG   fPolicyTurnOffSingleAppMode : 1;
     ULONG   fTurnOffSingleAppMode : 1;
     ULONG   fDisablePNPPolicyIsEnfored:1;
     ULONG   fDisablePNPPolicyValue:1;
     ULONG   MaxInstanceCount;
     ULONG   LicensingMode;  
     BYTE    MinEncryptionLevel;
     WCHAR   WFProfilePath[ DIRECTORY_LENGTH + 1 ];
     WCHAR   WFHomeDir[ DIRECTORY_LENGTH + 1 ];
     WCHAR   WFHomeDirDrive[ 4 ];
     ULONG   SessionDirectoryActive;
     WCHAR   SessionDirectoryLocation[DIRECTORY_LENGTH+1];
     WCHAR   SessionDirectoryClusterName[DIRECTORY_LENGTH+1];
     WCHAR   SessionDirectoryAdditionalParams[DIRECTORY_LENGTH+1];
     ULONG   SessionDirectoryExposeServerIP;
     ULONG   KeepAliveInterval;
     SHADOWCLASS     Shadow;
     ULONG   MaxConnectionTime;          
     ULONG   MaxDisconnectionTime;       
     ULONG   MaxIdleTime;        
     WCHAR   WorkDirectory[ DIRECTORY_LENGTH + 1 ];
     WCHAR   InitialProgram[ INITIALPROGRAM_LENGTH + 1 ];
     WCHAR   LicenseServers[MAX_LICENSE_SERVER_LENGTH + 1 ];
 } POLICY_TS_MACHINE, *PPOLICY_TS_MACHINE;
  
 /*
 *  User Configuration data
 */
  
 typedef struct _USERCONFIG {
     /* if flag is set inherit parameter from user or client configuration */
     ULONG fInheritAutoLogon : 1;
     ULONG fInheritResetBroken : 1;
     ULONG fInheritReconnectSame : 1;
     ULONG fInheritInitialProgram : 1;
     ULONG fInheritCallback : 1;
     ULONG fInheritCallbackNumber : 1;
     ULONG fInheritShadow : 1;
     ULONG fInheritMaxSessionTime : 1;
     ULONG fInheritMaxDisconnectionTime : 1;
     ULONG fInheritMaxIdleTime : 1;
     ULONG fInheritAutoClient : 1;
     ULONG fInheritSecurity : 1;
     ULONG fPromptForPassword : 1;
     ULONG fResetBroken : 1;
     ULONG fReconnectSame : 1;
     ULONG fLogonDisabled : 1;
     ULONG fWallPaperDisabled : 1;
     ULONG fAutoClientDrives : 1;
     ULONG fAutoClientLpts : 1;
     ULONG fForceClientLptDef : 1;
     ULONG fRequireEncryption : 1;
     ULONG fDisableEncryption : 1;
     ULONG fUnused1 : 1;
     ULONG fHomeDirectoryMapRoot : 1;
     ULONG fUseDefaultGina : 1;
     ULONG fCursorBlinkDisabled : 1;
     ULONG fPublishedApp : 1;
     ULONG fHideTitleBar : 1;
     ULONG fMaximize : 1;
     ULONG fDisableCpm : 1;
     ULONG fDisableCdm : 1;
     ULONG fDisableCcm : 1;
     ULONG fDisableLPT : 1;
     ULONG fDisableClip : 1;
     ULONG fDisableExe : 1;
     ULONG fDisableCam : 1;
     ULONG fDisableAutoReconnect : 1;
     ULONG ColorDepth : 3;
     ULONG fInheritColorDepth: 1;
     ULONG   fErrorInvalidProfile : 1;
     ULONG fPasswordIsScPin: 1;
     ULONG   fDisablePNPRedir:1;
     WCHAR UserName[ USERNAME_LENGTH + 1 ];
     WCHAR Domain[ DOMAIN_LENGTH + 1 ];
     WCHAR Password[ PASSWORD_LENGTH + 1 ];
     WCHAR WorkDirectory[ DIRECTORY_LENGTH + 1 ];
     WCHAR InitialProgram[ INITIALPROGRAM_LENGTH + 1 ];
     WCHAR CallbackNumber[ CALLBACK_LENGTH + 1 ];
     CALLBACKCLASS Callback;
     SHADOWCLASS Shadow;
     ULONG MaxConnectionTime;
     ULONG MaxDisconnectionTime;
     ULONG MaxIdleTime;
     ULONG KeyboardLayout;
     BYTE MinEncryptionLevel;
     WCHAR NWLogonServer[ NASIFILESERVER_LENGTH + 1 ];
     APPLICATIONNAME PublishedName;
     WCHAR WFProfilePath[ DIRECTORY_LENGTH + 1 ];
     WCHAR WFHomeDir[ DIRECTORY_LENGTH + 1 ];
     WCHAR WFHomeDirDrive[ 4 ];
 } USERCONFIG, * PUSERCONFIG;
  
 /******************
 *  PD structures
 ******************/
  
 typedef struct _PDCONFIG2{
     PDNAME PdName;        
     SDCLASS SdClass;       
     DLLNAME PdDLL;        
     ULONG    PdFlag;       
     ULONG OutBufLength;    
     ULONG OutBufCount;     
     ULONG OutBufDelay;     
     ULONG InteractiveDelay;
     ULONG PortNumber;      
     ULONG KeepAliveTimeout;
 } PDCONFIG2, * PPDCONFIG2;
  
 /*
 *  PdFlag defines
 */
  
 #define PD_UNUSED      0x00000001  
 #define PD_RELIABLE    0x00000002  
 #define PD_FRAME       0x00000004  
 #define PD_CONNECTION  0x00000008  
 #define PD_CONSOLE     0x00000010  
 #define PD_LANA        0x00000020  
 #define PD_TRANSPORT   0x00000040  
 #define PD_SINGLE_INST 0x00000080  
 #define PD_NOLOW_WATERMARK 0x00000100
  
 /*------------------------------------------------*/
 typedef enum _RECEIVEFLOWCONTROLCLASS {
     ReceiveFlowControl_None,
     ReceiveFlowControl_RTS,
     ReceiveFlowControl_DTR,
 } RECEIVEFLOWCONTROLCLASS;
  
 typedef enum _TRANSMITFLOWCONTROLCLASS {
     TransmitFlowControl_None,
     TransmitFlowControl_CTS,
     TransmitFlowControl_DSR,
 } TRANSMITFLOWCONTROLCLASS;
  
 typedef struct _FLOWCONTROLCONFIG {
     ULONG fEnableSoftwareTx: 1;
     ULONG fEnableSoftwareRx: 1;
     ULONG fEnableDTR: 1;
     ULONG fEnableRTS: 1;
     CHAR XonChar;
     CHAR XoffChar;
     FLOWCONTROLCLASS Type;
     RECEIVEFLOWCONTROLCLASS HardwareReceive;
     TRANSMITFLOWCONTROLCLASS HardwareTransmit;
 } FLOWCONTROLCONFIG, * PFLOWCONTROLCONFIG;
  
 typedef  enum  _ASYNCCONNECTCLASS {
     Connect_CTS,
     Connect_DSR,
     Connect_RI,
     Connect_DCD,
     Connect_FirstChar,
     Connect_Perm,
 }  ASYNCCONNECTCLASS; 
  
 typedef struct _CONNECTCONFIG {
     ASYNCCONNECTCLASS Type;
     ULONG fEnableBreakDisconnect: 1;
 } CONNECTCONFIG, * PCONNECTCONFIG;
 /*------------------------------------------------*/
  
 typedef struct _ASYNCCONFIG {
     DEVICENAME DeviceName;
     MODEMNAME ModemName;
     ULONG BaudRate;
     ULONG Parity;
     ULONG StopBits;
     ULONG ByteSize;
     ULONG fEnableDsrSensitivity: 1;
     ULONG fConnectionDriver: 1;
     FLOWCONTROLCONFIG FlowControl;
     CONNECTCONFIG Connect;
 } ASYNCCONFIG, * PASYNCCONFIG;
  
 /*------------------------------------------------*/
  
 typedef struct _NETWORKCONFIG {
     LONG LanAdapter;
     DEVICENAME NetworkName;
     ULONG Flags;
 } NETWORKCONFIG, * PNETWORKCONFIG;
  
 /*------------------------------------------------*/
  
 typedef struct _NASICONFIG {
     NASISPECIFICNAME    SpecificName;
     NASIUSERNAME        UserName;
     NASIPASSWORD        PassWord;
     NASISESIONNAME      SessionName;
     NASIFILESERVER      FileServer;
     BOOLEAN              GlobalSession;
 } NASICONFIG, * PNASICONFIG;
  
 /*------------------------------------------------*/
  
 typedef struct _OEMTDCONFIG {
     LONG Adapter;
     DEVICENAME DeviceName;
     ULONG Flags;
 } OEMTDCONFIG, * POEMTDCONFIG;
  
 /*------------------------------------------------*/
  
 typedef struct _PDPARAMS {
     SDCLASS SdClass;
     union {
         NETWORKCONFIG Network;
         ASYNCCONFIG Async;
         NASICONFIG Nasi;
         OEMTDCONFIG OemTd;
     };
 } PDPARAMS, * PPDPARAMS;
  
 /*------------------------------------------------*/
  
 typedef struct _PDCONFIG {
     PDCONFIG2 Create;
     PDPARAMS Params;
 } PDCONFIG, * PPDCONFIG;
  
 /***********************
 *  Wd structures
 ***********************/
  
 typedef struct _WDCONFIG {
     WDNAME WdName;
     DLLNAME WdDLL;
     DLLNAME WsxDLL;
     ULONG WdFlag;
     ULONG WdInputBufferLength;
     DLLNAME CfgDLL;
     WDPREFIX WdPrefix;
 } WDCONFIG, * PWDCONFIG;
  
 /*
 *  WdFlag defines
 */
  
 #define WDF_UNUSED            0x00000001  
 #define WDF_SHADOW_SOURCE     0x00000002  
 #define WDF_SHADOW_TARGET     0x00000004  
 #define WDF_OTHER             0x00000008  
 #define WDF_TSHARE            0x00000010  
 #define WDF_DYNAMIC_RECONNECT 0x00000020  
 #define WDF_USER_VCIOCTL      0x00000040 
 #define WDF_SUBDESKTOP        0x00008000 
  
 /**************************************
 *  Connection Driver structures (CD)
 **************************************/
  
 /*
 *  connection driver classes
 */
  
 typedef enum _CDCLASS {
     CdNone,           
     CdModem,          
     CdClass_Maximum,  
 } CDCLASS;
  
 /*------------------------------------------------*/
  
 typedef struct _CDCONFIG {
     CDCLASS CdClass;
     CDNAME CdName;
     DLLNAME CdDLL;
     ULONG CdFlag;
 } CDCONFIG, * PCDCONFIG;
  
 /*****************************
 *  Window Station structures
 *****************************/
  
 typedef struct _WINSTATIONCREATE {
     ULONG fEnableWinStation : 1;
     ULONG MaxInstanceCount;
 } WINSTATIONCREATE, * PWINSTATIONCREATE;
  
 /*------------------------------------------------*/
  
 typedef struct _WINSTATIONCONFIG {
     WCHAR Comment[ WINSTATIONCOMMENT_LENGTH + 1 ];
     USERCONFIG User;
     char OEMId[4];               
 } WINSTATIONCONFIG, * PWINSTATIONCONFIG;
  
 /*------------------------------------------------*/
  
 typedef  enum  _SessionType  {
      SESSIONTYPE_UNKNOWN = 0,
      SESSIONTYPE_SERVICES,
      SESSIONTYPE_LISTENER,
      SESSIONTYPE_REGULARDESKTOP,
      SESSIONTYPE_ALTERNATESHELL,
      SESSIONTYPE_REMOTEAPP,
      SESSIONTYPE_MEDIACENTEREXT
 }  SESSIONTYPE;
  
 /*------------------------------------------------*/
  
 #define EXECSRVPIPENAMELEN 48
  
 typedef enum _WINSTATIONINFOCLASS {
     WinStationCreateData,   
     WinStationConfiguration,
     WinStationPdParams,     
     WinStationWd,           
     WinStationPd,           
     WinStationPrinter,      
     WinStationClient,       
     WinStationModules,      
     WinStationInformation,  
     WinStationTrace,        
     WinStationBeep,         
     WinStationEncryptionOff,
     WinStationEncryptionPerm,
     WinStationNtSecurity,    
     WinStationUserToken,     
     WinStationUnused1,       
     WinStationVideoData,     
     WinStationInitialProgram,
     WinStationCd,            
     WinStationSystemTrace,   
     WinStationVirtualData,   
     WinStationClientData,    
     WinStationSecureDesktopEnter,
     WinStationSecureDesktopExit, 
     WinStationLoadBalanceSessionTarget,
     WinStationLoadIndicator,      
     WinStationShadowInfo,         
     WinStationDigProductId,     
     WinStationLockedState,      
     WinStationRemoteAddress,    
     WinStationIdleTime,         
     WinStationLastReconnectType, 
     WinStationDisallowAutoReconnect,
     WinStationUnused2,      
     WinStationUnused3,  
     WinStationUnused4, 
     WinStationUnused5,    
     WinStationReconnectedFromId,  
     WinStationEffectsPolicy,
     WinStationType,
     WinStationInformationEx       
 } WINSTATIONINFOCLASS;
  
 /*------------------------------------------------*/
  
 typedef struct _WINSTATIONCLIENTDATA {
     CLIENTDATANAME DataName;
     BOOLEAN fUnicodeData;
     /* BYTE   Data[1]; Variable length data follows */
 } WINSTATIONCLIENTDATA, * PWINSTATIONCLIENTDATA;
  
 /*------------------------------------------------*/
  
 typedef struct _WINSTATIONUSERTOKEN {
     HANDLE ProcessId;
     HANDLE ThreadId;
     HANDLE UserToken;
 } WINSTATIONUSERTOKEN, * PWINSTATIONUSERTOKEN;
  
 /*------------------------------------------------*/
  
 typedef struct _WINSTATIONVIDEODATA {
     USHORT  HResolution;
     USHORT  VResolution;
     USHORT  fColorDepth;
 } WINSTATIONVIDEODATA, *PWINSTATIONVIDEODATA;
  
 /*----------------------------------------------*/
  
 typedef struct _WINSTATIONCONFIG2 {
     WINSTATIONCREATE Create;
     PDCONFIG Pd[ MAX_PDCONFIG ];
     WDCONFIG Wd;
     CDCONFIG Cd;
     WINSTATIONCONFIG   Config;
 } WINSTATIONCONFIG2, * PWINSTATIONCONFIG2;
  
 /*
 *  WinStation client data structure
 */
  
 typedef struct _WINSTATIONCLIENT {
     ULONG fTextOnly: 1;
     ULONG fDisableCtrlAltDel: 1;
     ULONG fMouse: 1;
     ULONG fDoubleClickDetect: 1;
     ULONG fINetClient: 1;
     ULONG fPromptForPassword : 1;
     ULONG fMaximizeShell: 1;
     ULONG fEnableWindowsKey: 1;
     ULONG fRemoteConsoleAudio: 1;
     ULONG fPasswordIsScPin: 1;
     ULONG fNoAudioPlayback: 1;
     ULONG fUsingSavedCreds: 1;
     ULONG fRestrictedLogon: 1;
     WCHAR ClientName[ CLIENTNAME_LENGTH + 1 ];
     WCHAR Domain[ DOMAIN_LENGTH + 1 ];
     WCHAR UserName[ USERNAME_LENGTH + 1 ];
     WCHAR Password[ PASSWORD_LENGTH + 1 ];
     WCHAR WorkDirectory[ DIRECTORY_LENGTH + 1 ];
     WCHAR InitialProgram[ INITIALPROGRAM_LENGTH + 1 ];
     ULONG SerialNumber;         
     BYTE EncryptionLevel;       
     ULONG ClientAddressFamily;
     WCHAR ClientAddress[ CLIENTADDRESS_LENGTH + 1 ];
     USHORT HRes;
     USHORT VRes;
     USHORT ColorDepth;
     USHORT ProtocolType;   
     ULONG KeyboardLayout;
     ULONG KeyboardType;
     ULONG KeyboardSubType;
     ULONG KeyboardFunctionKey;
     WCHAR imeFileName[ IMEFILENAME_LENGTH + 1 ];
     WCHAR ClientDirectory[ DIRECTORY_LENGTH + 1 ];
     WCHAR ClientLicense[ CLIENTLICENSE_LENGTH + 1 ];
     WCHAR ClientModem[ CLIENTMODEM_LENGTH + 1 ];
     ULONG ClientBuildNumber;
     ULONG ClientHardwareId;
     USHORT ClientProductId;   
     USHORT OutBufCountHost;   
     USHORT OutBufCountClient; 
     USHORT OutBufLength;      
     WCHAR AudioDriverName[9];
     TS_TIME_ZONE_INFORMATION ClientTimeZone;
     ULONG ClientSessionId;
     WCHAR clientDigProductId[CLIENT_PRODUCT_ID_LENGTH];
     ULONG PerformanceFlags;  
     ULONG ActiveInputLocale; 
 } WINSTATIONCLIENT, * PWINSTATIONCLIENT;
  
 /*
 *  T.Share specific protocol performance counters
 */
  
 typedef struct _TSHARE_COUNTERS {
     ULONG Reserved;
 } TSHARE_COUNTERS, * PTSHARE_COUNTERS;
  
 /*
 *  WinStation protocol performance counters
 */
  
 typedef struct _PROTOCOLCOUNTERS {
     ULONG WdBytes;             
     ULONG WdFrames;            
     ULONG WaitForOutBuf;       
     ULONG Frames;              
     ULONG Bytes;               
     ULONG CompressedBytes;     
     ULONG CompressFlushes;     
     ULONG Errors;              
     ULONG Timeouts;            
     ULONG AsyncFramingError;   
     ULONG AsyncOverrunError;   
     ULONG AsyncOverflowError;  
     ULONG AsyncParityError;    
     ULONG TdErrors;            
     USHORT ProtocolType;       
     USHORT Length;             
     union {
         TSHARE_COUNTERS TShareCounters;
         ULONG           Reserved[100];
     } Specific;
 } PROTOCOLCOUNTERS, * PPROTOCOLCOUNTERS;
  
 /*
 * ThinWire cache statistics
 */
  
 typedef struct _THINWIRECACHE {
     ULONG CacheReads;
     ULONG CacheHits;
 } THINWIRECACHE, * PTHINWIRECACHE;
 #define MAX_THINWIRECACHE   4
  
  
 typedef struct _RESERVED_CACHE {
     THINWIRECACHE ThinWireCache[ MAX_THINWIRECACHE ];
 } RESERVED_CACHE, * PRESERVED_CACHE;
  
 /*
 *  T.Share specific cache statistics
 */
  
 typedef struct _TSHARE_CACHE {
     ULONG Reserved;
 } TSHARE_CACHE, * PTSHARE_CACHE;
  
 /*
 *  WinStation cache statistics
 */
  
 typedef struct CACHE_STATISTICS {
     USHORT ProtocolType;    
     USHORT Length;          
     union {
         RESERVED_CACHE    ReservedCacheStats;
         TSHARE_CACHE TShareCacheStats;
         ULONG        Reserved[20];
     } Specific;
 } CACHE_STATISTICS, * PCACHE_STATISTICS;
  
 /*
 *  WinStation protocol status
 */
  
 typedef struct _PROTOCOLSTATUS {
     PROTOCOLCOUNTERS Output;
     PROTOCOLCOUNTERS Input;
     CACHE_STATISTICS Cache;
     ULONG AsyncSignal;     
     ULONG AsyncSignalMask; 
 } PROTOCOLSTATUS, * PPROTOCOLSTATUS;
  
 #ifdef __cplusplus
 typedef struct _PROTOCOLSTATUSEX : PROTOCOLSTATUS {
 #else
 typedef struct _PROTOCOLSTATUSEX {
     PROTOCOLSTATUS ;
 #endif  
     LARGE_INTEGER  Counters[MAX_COUNTER_EXTENSIONS];
 } PROTOCOLSTATUSEX, *PPROTOCOLSTATUSEX;
  
 /*
 *  WinStation query information
 */
  
 typedef struct _WINSTATIONINFORMATION {
     WINSTATIONSTATECLASS ConnectState;
     WINSTATIONNAME WinStationName;
     ULONG LogonId;
     LARGE_INTEGER ConnectTime;
     LARGE_INTEGER DisconnectTime;
     LARGE_INTEGER LastInputTime;
     LARGE_INTEGER LogonTime;
     PROTOCOLSTATUS Status;
     WCHAR Domain[ DOMAIN_LENGTH + 1 ];
     WCHAR UserName[USERNAME_LENGTH + 1];
     LARGE_INTEGER CurrentTime;
 } WINSTATIONINFORMATION, * PWINSTATIONINFORMATION;
  
 /*
 * Load balancing data types
 */
  
 typedef enum _LOADFACTORTYPE {
     ErrorConstraint,
     PagedPoolConstraint,
     NonPagedPoolConstraint,
     AvailablePagesConstraint,
     SystemPtesConstraint,
     CPUConstraint
 } LOADFACTORTYPE;
  
 typedef struct _WINSTATIONLOADINDICATORDATA {
     ULONG RemainingSessionCapacity;
     LOADFACTORTYPE LoadFactor;
     ULONG TotalSessions;
     ULONG DisconnectedSessions;
     LARGE_INTEGER IdleCPU;
     LARGE_INTEGER TotalCPU;
     ULONG RawSessionCapacity;
     ULONG reserved[9];  
 } WINSTATIONLOADINDICATORDATA, * PWINSTATIONLOADINDICATORDATA;
  
 /*
 *  WinStation shadow states
 */
  
 typedef enum _SHADOWSTATECLASS {
     State_NoShadow,   
     State_Shadowing,  
     State_Shadowed,   
 } SHADOWSTATECLASS;
  
 /*
 *  Shadow query/set information
 */
  
 typedef struct _WINSTATIONSHADOW {
     SHADOWSTATECLASS    ShadowState;
     SHADOWCLASS         ShadowClass;
     ULONG               SessionId;
     ULONG               ProtocolType; 
 } WINSTATIONSHADOW, * PWINSTATIONSHADOW;
  
 typedef struct _WINSTATIONPRODID {
     WCHAR DigProductId[CLIENT_PRODUCT_ID_LENGTH];
     WCHAR ClientDigProductId[CLIENT_PRODUCT_ID_LENGTH ];
     WCHAR OuterMostDigProductId[CLIENT_PRODUCT_ID_LENGTH ];
     ULONG curentSessionId;
     ULONG ClientSessionId;
     ULONG OuterMostSessionId;
 }WINSTATIONPRODID, *PWINSTATIONPRODID;
  
 typedef struct {
     unsigned short sin_family;
     union {
         struct {
             USHORT sin_port;
             ULONG  in_addr;
             UCHAR  sin_zero[8];
         } ipv4;
         struct {
             USHORT sin6_port;
             ULONG  sin6_flowinfo;
             USHORT sin6_addr[8];
             ULONG  sin6_scope_id;
         } ipv6;
     };
 } WINSTATIONREMOTEADDRESS, *PWINSTATIONREMOTEADDRESS;
  
 #define DEFAULT_POLICY_ID       1
 #define PERSEAT_POLICY_ID       2
 #define INTCONN_POLICY_ID       3
 #define PERUSER_POLICY_ID       4
 #define POLICY_NOT_CONFIGURED   5
 #define MAXIMUM_POLICY_ID       6
  
 /*------------------------------------------------*/
  
 typedef struct _BEEPINPUT {
     ULONG uType;
 } BEEPINPUT, * PBEEPINPUT;
  
 /**********************
 *  NWLogon Structure
 **********************/
  
 #define IDTIMEOUT        32000 
 #define IDASYNC          32001 
 #define WSD_LOGOFF      0x00000001
 #define WSD_SHUTDOWN    0x00000002
 #define WSD_REBOOT      0x00000004
 #define WSD_POWEROFF    0x00000008
 #define WSD_FASTREBOOT  0x00000010
  
 #define WTS_CONSOLE_CONNECT                0x1
 #define WTS_CONSOLE_DISCONNECT             0x2
 #define WTS_REMOTE_CONNECT                 0x3
 #define WTS_REMOTE_DISCONNECT              0x4
 #define WTS_SESSION_LOGON                  0x5
 #define WTS_SESSION_LOGOFF                 0x6
 #define WTS_SESSION_LOCK                   0x7
 #define WTS_SESSION_UNLOCK                 0x8
 #define WTS_SESSION_REMOTE_CONTROL         0x9
  
 #define CREATE_MASK(__bit)   (1 << (__bit -1) )
 #define WTS_CONSOLE_CONNECT_MASK         CREATE_MASK( WTS_CONSOLE_CONNECT )
 #define WTS_CONSOLE_DISCONNECT_MASK      CREATE_MASK( WTS_CONSOLE_DISCONNECT )
 #define WTS_REMOTE_CONNECT_MASK          CREATE_MASK( WTS_REMOTE_CONNECT )
 #define WTS_REMOTE_DISCONNECT_MASK       CREATE_MASK( WTS_REMOTE_DISCONNECT )
 #define WTS_SESSION_LOGON_MASK           CREATE_MASK( WTS_SESSION_LOGON )
 #define WTS_SESSION_LOGOFF_MASK          CREATE_MASK( WTS_SESSION_LOGOFF )
 #define WTS_SESSION_LOCK_MASK            CREATE_MASK( WTS_SESSION_LOCK )
 #define WTS_SESSION_UNLOCK_MASK          CREATE_MASK( WTS_SESSION_UNLOCK )
 #define WTS_SESSION_REMOTE_CONTROL_MASK  CREATE_MASK( WTS_SESSION_REMOTE_CONTROL )
 #define WTS_ALL_NOTIFICATION_MASK        0xFFFFFFFF
  
  
 typedef struct _SESSIONID {
     union {
         ULONG SessionId;
         ULONG LogonId;
     } _SessionId_LogonId_union;
     WINSTATIONNAME WinStationName;
     WINSTATIONSTATECLASS State;
 } SESSIONID, *PSESSIONID;
  
  
 #define LOGINID SESSIONID
 #define PLOGINID PSESSIONID
  
  
 #define TS_USER_AUTHENTICATION_NONE        0
 #define TS_USER_AUTHENTICATION_VIA_HYBRID  1
 #define TS_USER_AUTHENTICATION_VIA_SSL     2
 #define TS_USER_AUTHENTICATION_DEFAULT     TS_USER_AUTHENTICATION_NONE
  
 typedef struct _VARDATA_WIRE {
     USHORT Size;
     USHORT Offset;
 } VARDATA_WIRE, *PVARDATA_WIRE;
  
 typedef struct _PDPARAMSWIRE {
     SDCLASS SdClass;
     VARDATA_WIRE SdClassSpecific;
 } PDPARAMSWIRE, *PPDPARAMSWIRE;
  
 typedef struct _WINSTACONFIGWIRE {
     WCHAR Comment[61];
     char OEMId[4];
     VARDATA_WIRE UserConfig;
      VARDATA_WIRE NewFields;
 } WINSTACONFIGWIRE, *PWINSTACONFIGWIRE;
  
 #define  PRODUCTINFO_COMPANYNAME_LENGTH   256
 #define  PRODUCTINFO_PRODUCTID_LENGTH       4
  
 typedef struct _WINSTATIONPRODUCTINFO  {
     WCHAR  CompanyName[PRODUCTINFO_COMPANYNAME_LENGTH];
     WCHAR  ProductID[PRODUCTINFO_PRODUCTID_LENGTH];
 }  WINSTATIONPRODUCTINFO,  *PWINSTATIONPRODUCTINFO;
  
 #define  VALIDATIONINFORMATION_LICENSE_LENGTH      16384
 #define  VALIDATIONINFORMATION_HARDWAREID_LENGTH      20
  
 typedef struct  _WINSTATIONVALIDATIONINFORMATION  {
     WINSTATIONPRODUCTINFO    ProductInfo;
     BYTE                 License[VALIDATIONINFORMATION_LICENSE_LENGTH];
     ULONG                LicenseLength;
     BYTE                 HardwareID[VALIDATIONINFORMATION_HARDWAREID_LENGTH];
     ULONG                HardwareIDLength;
 }  WINSTATIONVALIDATIONINFORMATION,  *PWINSTATIONVALIDATIONINFORMATION;
  
  