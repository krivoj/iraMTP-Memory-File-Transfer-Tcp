
unit iraMtpSrv;

{$B-}           { Enable partial boolean evaluation   }
{$T-}           { Untyped pointers                    }
{$X+}           { Enable extended syntax              }
{$H+}           { Use long strings                    }
{$J+}           { Allow typed constant to be modified }
interface

uses
    Winapi.Windows,
    Winapi.Messages,
    OverbyteIcsWinSock,
    System.SysUtils,
    System.Classes,
{$IFNDEF NOFORMS}
  {$IFDEF FMX}
    FMX.Forms,
  {$ELSE}
    Vcl.Forms,
  {$ENDIF}
{$ENDIF}

    OverbyteIcsTypes,
    OverbyteIcsUtils,
  {$IFDEF FMX}
    Ics.Fmx.OverbyteIcsSocketUtils,
    Ics.Fmx.OverbyteIcsWndControl,
    Ics.Fmx.OverbyteIcsWSocket,
    Ics.Fmx.OverbyteIcsWSocketS,
  {$ELSE}
    OverbyteIcsWndControl,
    OverbyteIcsWSocket,
    OverbyteIcsSocketUtils,
    OverbyteIcsWSocketS,
  {$ENDIF}
    OverbyteIcsFtpSrvT,
    OverbyteIcsWSockBuf,
    StrUtils
    ;



const
    DefaultRcvSize           = 16384;

const
    ftpcPORT      = 0;
    ftpcSTOR      = 1;
    ftpcRETR      = 2;
    ftpcQUIT      = 3;
    ftpcABOR      = 4;


type

    PBoolean = ^Boolean;
    FtpServerException  = class(Exception);
    TFtpString = type String;


type
    EFtpCtrlSocketException = class(Exception);
    TFtpCtrlState = (ftpcInvalid, ftpcWaitingUserCode,
                     ftpcReady, ftpcWaitingAnswer, ftpcFailedAuth);

    TFtpCmdType   = Byte;

type
    TDisplayEvent = procedure (Sender : TObject; Msg : String) of object;
    TCommandEvent = procedure (Sender : TObject; CmdBuf : PAnsiChar; CmdLen : Integer) of object;

    TMtpCtrlSocket = class;

    TClientProcessingThread = class(TThread)
    public
        Client    : TMtpCtrlSocket;
        Keyword   : String;
        Params    : String;
        InData    : String;
        OutData   : String;
        AuxData   : String;
        ClientID  : Integer;
        StartTick : LongWord;
        Sender    : TObject;
    protected
        procedure TriggerEnterSecurityContext;
        procedure TriggerLeaveSecurityContext;
        procedure Execute; override;
    end;

    TMtpServer     = class;

    TMtpCtrlSocket = class(TWSocketClient)
    protected
        FDataSocket        : TWSocket;
        FRcvBuf            : PAnsiChar;
        FRcvCnt            : Integer;
        FRcvSize           : Integer;
        FBusy              : Boolean;
        FLastCommand       : TDateTime;
        FCommandCount      : LongInt;
        FCloseRequest      : Boolean;
        FFtpState          : TFtpCtrlState;
        FAbortingTransfer  : Boolean;
        FUserData          : LongInt;
        FPeerAddr          : String;
        FPeerSAddr         : TSockAddr;
        FHost              : String;
        FOnDisplay         : TDisplayEvent;
        FOnCommand         : TCommandEvent;
        FEpsvAllArgReceived: Boolean;
        FSndBufSize        : Integer;
        FRcvBufSize        : Integer;
        FStreamSize        : LongInt;
        procedure TriggerSessionConnected(Error : Word); override;
        function  TriggerDataAvailable(Error : Word) : boolean; override;
        procedure TriggerCommand(CmdBuf : PAnsiChar; CmdLen : Integer); virtual;
        procedure SetRcvSize(newValue : Integer);
        procedure SetOnBgException(const Value: TIcsBgExceptionEvent); override;
        procedure SetRcvBufSize(newValue : Integer);
        procedure SetSndBufSize(newValue : Integer);
        procedure SetStreamSize(newValue : Integer);
    public
        FtpServer         : TMtpServer;
        BinaryMode        : Boolean;
        DataAddr          : String;
        DataPort          : String;
        MemoryName        : String;
        DataSessionActive : Boolean;
        DataStream        : TMemoryStream;
        HasOpenedFile     : Boolean;
        TransferError     : String;
        DataSent          : Boolean;
        CurCmdType        : TFtpCmdType;
        ProcessingThread  : TClientProcessingThread;
        AnswerDelayed     : Boolean;
        ByteCount         : Int64;
        RestartPos        : Int64;
        LastTick          : Longword;
        SessStartTick     : Longword;
        ReqStartTick      : Longword;
        XferStartTick     : Longword;
        ReqDurMilliSecs   : Integer;
        TotGetBytes       : Int64;
        TotPutBytes       : Int64;
        SessIdInfo        : String;
        FailedAttempts    : Integer;
        DelayAnswerTick   : Longword;
        constructor Create(AOwner: TComponent); override;
        destructor  Destroy; override;
        procedure   SendAnswer(const Answer : RawByteString);
        procedure   SetAbortingTransfer(newValue : Boolean);
        procedure   TriggerSessionClosed(Error : Word); override;
        procedure   DataStreamWriteString(const Str: AnsiString);  overload;
        procedure   DataStreamWriteString(const Str: AnsiString; DstCodePage: LongWord);  overload;

        procedure   DataStreamWriteString(const Str: UnicodeString; DstCodePage: LongWord); overload;
        procedure   DataStreamWriteString(const Str: UnicodeString); overload;

        procedure   DataStreamReadString(var Str: AnsiString; Len: TFtpBigInt); overload;
        procedure   DataStreamReadString(var Str: AnsiString; Len: TFtpBigInt; SrcCodePage: LongWord); overload;

        procedure   DataStreamReadString(var Str: UnicodeString; Len: TFtpBigInt); overload;

        property    DataSocket     : TWSocket    read  FDataSocket;
        property    LastCommand    : TDateTime   read  FLastCommand;
        property    CommandCount   : LongInt     read  FCommandCount;
        property    RcvBuf         : PAnsiChar   read  FRcvBuf;
        property    RcvdCount;
        property    CloseRequest   : Boolean     read  FCloseRequest write FCloseRequest;
        property    AbortingTransfer : Boolean   read  FAbortingTransfer write SetAbortingTransfer;
        property    ID             : LongInt     read  FCliId write FCliId;
        property    PeerSAddr      : TSockAddr   read  FPeerSAddr;
        property    ReadCount      : Int64       read  FReadCount;

    published
        property    FtpState       : TFtpCtrlState  read  FFtpState write FFtpState;
        property    RcvSize        : Integer     read  FRcvSize write SetRcvSize;
        property    Busy           : Boolean     read  FBusy write FBusy;
        property    UserData       : LongInt     read  FUserData write FUserData;
        property    Host           : String      read  FHost write FHost;
        property    SndBufSize     : Integer     read FSndBufSize write SetSndBufSize;
        property    RcvBufSize     : Integer     read FRcvBufSize write SetRcvBufSize;
        property    StreamSize     : Integer     read FStreamSize write SetStreamSize;
        property    OnDisplay      : TDisplayEvent read  FOnDisplay write FOnDisplay;
        property    OnCommand      : TCommandEvent read  FOnCommand write FOnCommand;
        property    OnSessionClosed;
        property    OnDataSent;
        property    HSocket;
        property    AllSent;
        property    State;
    end;

    TMtpCtrlSocketClass = class of TMtpCtrlSocket;
    TFtpSrvClientConnectEvent = procedure (Sender: TObject; Client: TMtpCtrlSocket; AError: Word) of object;
    TFtpSrvDataSessionConnectedEvent = procedure (Sender: TObject; Client: TMtpCtrlSocket; Data  : TWSocket; AError: Word) of object;
    TFtpSrvClientCommandEvent = procedure (Sender: TObject; Client: TMtpCtrlSocket; var Keyword : TFtpString; var Params: TFtpString;
                                           var Answer: TFtpString) of object;
    TFtpSrvAnswerToClientEvent = procedure (Sender: TObject; Client: TMtpCtrlSocket;  var Answer  : TFtpString) of object;
    TFtpSrvDataAvailableEvent = procedure (Sender: TObject; Client: TMtpCtrlSocket; Data : TWSocket; Buf: PAnsiChar; Len: LongInt;
                                          AError: Word) of object;
    TFtpSrvRetrDataSentEvent  = procedure (Sender: TObject; Client: TMtpCtrlSocket; Data : TWSocket; AError: Word) of object;
    TFtpSrvGetProcessingEvent = procedure (Sender  : TObject; Client: TMtpCtrlSocket; var DelayedSend: Boolean) of object;
    TFtpSrvCommandProc = procedure (Client: TMtpCtrlSocket; var Keyword: TFtpString; var Params  : TFtpString;                              var Answer  : TFtpString) of object;

    TFtpSrvCommandTableItem   = record
     KeyWord : String;
     Proc    : TFtpSrvCommandProc;
    end;

    TFtpSrvCommandTable = array of TFtpSrvCommandTableItem;

    TFtpSecurityContextEvent  = procedure (Sender: TObject;Client: TMtpCtrlSocket) of object;
    TFtpSrvGeneralEvent = procedure (Sender: TObject; Client: TMtpCtrlSocket; var Params: TFtpString; var Answer: TFtpString) of object;
    TFtpSrvTimeoutEvent =  procedure (Sender: TObject; Client: TMtpCtrlSocket; Duration: Integer; var Abort: Boolean) of object;
    TFtpSrvDisplayEvent = procedure (Sender: TObject; Client: TMtpCtrlSocket; Msg: TFtpString) of object;

    TMtpServer = class(TIcsWndControl)
    protected
        FAddr                   : String;
        FSocketFamily           : TSocketFamily;
        FPort                   : String;
        FListenBackLog          : Integer;
        FSocketServer           : TWSocketServer ;
        FClientClass            : TMtpCtrlSocketClass;
        FMaxClients             : LongInt;
        FCmdTable               : TFtpSrvCommandTable;
        FLastCmd                : Integer;
        FUserData               : LongInt;
        FTimeoutSecsLogin       : Integer;
        FTimeoutSecsIdle        : Integer;
        FTimeoutSecsXfer        : Integer;
        FEventTimer             : TIcsTimer;
        FAlloExtraSpace         : Integer;
        FMaxAttempts            : Integer;
        FBindFtpData            : Boolean;

        FMsg_WM_FTPSRV_CLOSE_REQUEST  : UINT;
        FMsg_WM_FTPSRV_ABORT_TRANSFER : UINT;
        FMsg_WM_FTPSRV_CLOSE_DATA     : UINT;
        FMsg_WM_FTPSRV_START_SEND     : UINT;
        FOnStart                : TNotifyEvent;
        FOnStop                 : TNotifyEvent;
        FOnClientConnect        : TFtpSrvClientConnectEvent;
        FOnClientDisconnect     : TFtpSrvClientConnectEvent;
        FOnClientCommand        : TFtpSrvClientCommandEvent;
        FOnAnswerToClient       : TFtpSrvAnswerToClientEvent;
        FOnStorSessionConnected : TFtpSrvDataSessionConnectedEvent;
        FOnStorSessionClosed    : TFtpSrvDataSessionConnectedEvent;
        FOnStorDataAvailable    : TFtpSrvDataAvailableEvent;
        FOnRetrSessionConnected : TFtpSrvDataSessionConnectedEvent;
        FOnRetrSessionClosed    : TFtpSrvDataSessionConnectedEvent;
        FOnRetrDataSent         : TFtpSrvRetrDataSentEvent;
        FOnGetProcessing        : TFtpSrvGetProcessingEvent;
        FOnEnterSecurityContext : TFtpSecurityContextEvent;
        FOnLeaveSecurityContext : TFtpSecurityContextEvent;
        FOnTimeout              : TFtpSrvTimeoutEvent;
        FOnDisplay              : TFtpSrvDisplayEvent;
        procedure CreateSocket; virtual;
        function  GetMultiListenIndex: Integer;
        function  GetMultiListenSockets: TWSocketMultiListenCollection;
        procedure SetMultiListenSockets(const Value: TWSocketMultiListenCollection);
        procedure SetOnBgException(const Value: TIcsBgExceptionEvent); override;

        procedure ClientProcessingThreadTerminate(Sender : TObject);
        procedure Notification(AComponent: TComponent; operation: TOperation); override;
        procedure ServSocketStateChange(Sender: TObject; OldState, NewState: TSocketState);
        procedure ClientDataSent(Sender: TObject; AError : Word); virtual;
        procedure ClientCommand(Sender: TObject; CmdBuf: PAnsiChar; CmdLen: Integer);
        procedure ClientStorSessionConnected(Sender: TObject; AError : Word);
        procedure ClientStorSessionClosed(Sender: TObject; AError : Word);
        procedure ClientStorDataAvailable(Sender: TObject; AError : word); virtual;
        procedure ClientRetrSessionConnected(Sender: TObject; AError : Word); virtual;
        procedure ClientRetrSessionClosed(Sender: TObject; AError : Word);
        procedure ClientRetrDataSent(Sender: TObject; AError : Word);
        procedure SendAnswer(Client: TMtpCtrlSocket; Answer: TFtpString);  virtual;
        procedure SendNextDataChunk(Client: TMtpCtrlSocket; Data: TWSocket); virtual;
        procedure StartSendData(Client: TMtpCtrlSocket);
        procedure PrepareStorDataSocket(Client: TMtpCtrlSocket);
        procedure EventTimerOnTimer(Sender: TObject);
        procedure ServerClientConnect(Sender: TObject; Client: TWSocketClient; Error: Word);
        procedure ServerClientDisconnect(Sender: TObject; Client: TWSocketClient; Error: Word);

        procedure TriggerServerStart; virtual;
        procedure TriggerServerStop; virtual;
        procedure TriggerSendAnswer(Client: TMtpCtrlSocket; var Answer: TFtpString); virtual;
        procedure TriggerClientConnect(Client: TMtpCtrlSocket; AError: Word); virtual;
        procedure TriggerClientDisconnect(Client: TMtpCtrlSocket; AError: Word); virtual;
        procedure TriggerClientCommand(Client: TMtpCtrlSocket; var Keyword: TFtpString; var Params: TFtpString; var Answer: TFtpString); virtual;
        procedure TriggerStorSessionConnected(Client: TMtpCtrlSocket; Data: TWSocket; AError: Word); virtual;
        procedure TriggerStorSessionClosed(Client: TMtpCtrlSocket; Data: TWSocket; AError: Word); virtual;
        procedure TriggerRetrSessionConnected(Client: TMtpCtrlSocket; Data: TWSocket; AError: Word); virtual;
        procedure TriggerRetrSessionClosed(Client: TMtpCtrlSocket; Data: TWSocket; AError: Word); virtual;
        procedure TriggerStorDataAvailable(Client: TMtpCtrlSocket; Data: TWSocket; Buf: PAnsiChar; Len: LongInt; AError: Word); virtual;
        procedure TriggerRetrDataSent(Client: TMtpCtrlSocket;Data: TWSocket; AError: Word); virtual;
        procedure TriggerEnterSecurityContext(Client: TMtpCtrlSocket); virtual;
        procedure TriggerLeaveSecurityContext(Client: TMtpCtrlSocket); virtual;
        procedure TriggerTimeout (Client: TMtpCtrlSocket; Duration: Integer; var Abort : Boolean); virtual;
        procedure TriggerDisplay (Client    : TMtpCtrlSocket; Msg: TFtpString); virtual;
        function  GetClientCount: Integer; virtual;
        function  GetClient(nIndex: Integer): TMtpCtrlSocket; virtual;
        function  GetActive: Boolean;
        procedure SetActive(newValue: Boolean);
        procedure SetClientClass(const NewValue: TMtpCtrlSocketClass);
        procedure AddCommand(const Keyword: String; const Proc: TFtpSrvCommandProc); virtual;
        procedure WMFtpSrvCloseRequest(var msg: TMessage); virtual;
        procedure WMFtpSrvAbortTransfer(var msg: TMessage); virtual;
        procedure WMFtpSrvCloseData(var msg: TMessage); virtual;
        procedure WMFtpSrvStartSend(var msg: TMessage); virtual;
        procedure CommandQUIT(Client: TMtpCtrlSocket; var Keyword: TFtpString; var Params: TFtpString; var Answer: TFtpString); virtual;
        procedure CommandPORT(Client: TMtpCtrlSocket; var Keyword: TFtpString; var Params: TFtpString; var Answer: TFtpString); virtual;
        procedure CommandSTOR(Client: TMtpCtrlSocket; var Keyword: TFtpString; var Params: TFtpString; var Answer: TFtpString); virtual;
        procedure CommandRETR(Client: TMtpCtrlSocket; var Keyword: TFtpString; var Params: TFtpString; var Answer: TFtpString); virtual;
        procedure CommandABOR(Client: TMtpCtrlSocket; var Keyword: TFtpString; var Params: TFtpString; var Answer: TFtpString); virtual;

    public
        constructor Create(AOwner: TComponent); override;
        destructor  Destroy; override;
        procedure   Start;
        procedure   Stop;
        procedure   Disconnect(Client : TMtpCtrlSocket);
        procedure   DisconnectAll;
        procedure   DoStartSendData(Client: TMtpCtrlSocket; var Answer : TFtpString); virtual;
        procedure   AllocateMsgHandlers; override;
        procedure   FreeMsgHandlers; override;
        function    MsgHandlersCount: Integer; override;
        procedure   WndProc(var MsgRec: TMessage); override;

        function    IsClient(SomeThing : TObject) : Boolean;
        function    OpenMemoryStream( ): TMemoryStream;
        procedure   CloseMemoryStreams(Client : TMtpCtrlSocket);
        property  ServSocket    : TWSocketServer      read  FSocketServer;
        property  ClientCount   : Integer             read  GetClientCount;
        property  Active        : Boolean             read  GetActive write SetActive;
        property  ClientClass   : TMtpCtrlSocketClass read  FClientClass write SetClientClass;

        property  Client[nIndex : Integer] : TMtpCtrlSocket read  GetClient;
        property  MultiListenIndex       : Integer    read  GetMultiListenIndex;
    published
        property  Addr                   : String     read  FAddr write FAddr;
        property  BindFtpData            : Boolean    read  FBindFtpData write FBindFtpData default True;
        property  SocketFamily           : TSocketFamily   read  FSocketFamily write FSocketFamily;
        property  Port                   : String     read  FPort write FPort;
        property  ListenBackLog          : Integer    read  FListenBackLog write FListenBackLog;
        property MultiListenSockets      : TWSocketMultiListenCollection read  GetMultiListenSockets write SetMultiListenSockets;
        property  UserData               : LongInt    read  FUserData write FUserData;
        property  MaxClients             : LongInt    read  FMaxClients write FMaxClients;
        property  TimeoutSecsLogin       : Integer    read FTimeoutSecsLogin write FTimeoutSecsLogin;
        property  TimeoutSecsIdle        : Integer    read FTimeoutSecsIdle write FTimeoutSecsIdle;
        property  TimeoutSecsXfer        : Integer    read FTimeoutSecsXfer write FTimeoutSecsXfer;
        property  AlloExtraSpace         : Integer    read FAlloExtraSpace write FAlloExtraSpace;
        property  MaxAttempts            : Integer    read  FMaxAttempts write FMaxAttempts ;
        property  OnStart                : TNotifyEvent read  FOnStart write FOnStart;
        property  OnStop                 : TNotifyEvent read  FOnStop write FOnStop;
        property  OnClientDisconnect     : TFtpSrvClientConnectEvent read  FOnClientDisconnect write FOnClientDisconnect;
        property  OnClientConnect        : TFtpSrvClientConnectEvent read  FOnClientConnect write FOnClientConnect;
        property  OnClientCommand        : TFtpSrvClientCommandEvent read  FOnClientCommand write FOnClientCommand;
        property  OnAnswerToClient       : TFtpSrvAnswerToClientEvent read  FOnAnswerToClient write FOnAnswerToClient;
        property  OnStorSessionConnected : TFtpSrvDataSessionConnectedEvent read  FOnStorSessionConnected write FOnStorSessionConnected;
        property  OnRetrSessionConnected : TFtpSrvDataSessionConnectedEvent read  FOnRetrSessionConnected  write FOnRetrSessionConnected;
        property  OnStorSessionClosed    : TFtpSrvDataSessionConnectedEvent read  FOnStorSessionClosed write FOnStorSessionClosed;
        property  OnRetrSessionClosed    : TFtpSrvDataSessionConnectedEvent read  FOnRetrSessionClosed write FOnRetrSessionClosed;
        property  OnRetrDataSent         : TFtpSrvRetrDataSentEvent read  FOnRetrDataSent write FOnRetrDataSent;
        property  OnStorDataAvailable    : TFtpSrvDataAvailableEvent read  FOnStorDataAvailable write FOnStorDataAvailable;
        property  OnGetProcessing        : TFtpSrvGetProcessingEvent read  FOnGetProcessing write FOnGetProcessing;
        property  OnEnterSecurityContext : TFtpSecurityContextEvent read  FOnEnterSecurityContext  write FOnEnterSecurityContext;
        property  OnLeaveSecurityContext : TFtpSecurityContextEvent read  FOnLeaveSecurityContext write FOnLeaveSecurityContext;
        property  OnTimeout              : TFtpSrvTimeoutEvent read  FOnTimeout write FOnTimeout;
        property  OnDisplay              : TFtpSrvDisplayEvent read  FOnDisplay write FOnDisplay;
        property  OnBgException;
    end;


procedure UpdateThreadOnProgress(Obj: TObject; Count: Int64; var Cancel: Boolean);

procedure register;
implementation


const
    msgCmdUnknown     = '500 ''%s'': command not understood.';
    msgOptRespRequired = '331 Response to %s required for %s.';
    msgQuit           = '221 Goodbye.';
    msgPortSuccess    = '200 Port command successful.';
    msgPortFailed     = '501 Invalid PORT command.';
    msgStorDisabled   = '501 Permission Denied'; {'500 Cannot STOR.';}
    msgStorSuccess    = '150 Opening data connection for %s.';
    msgStorFailed     = '501 Cannot STOR. %s';
    msgStorAborted    = '426 Connection closed; %s.';
    msgStorOk         = '226 File received ok';
{   msgStorOk         = '226-Multiple lines answer'#13#10'  Test'#13#10#13#10'226 File received OK'; }
    msgStorError      = '426 Connection closed; transfer aborted. Error %s';
    msgRetrDisabled   = '500 Cannot RETR.';
    msgRetrSuccess    = '150 Opening retrieve data connection for ';
    msgRetrFailed     = '501 Cannot RETR. %s';
    msgRetrAborted    = '426 Connection closed; %s.';
    msgRetrOk         = '226 File sent ok';
    msgRetrError      = '426 Connection closed; transfer aborted. Error %s';
    msgRetrNotExists  = '550 ''%s'': no such file or directory.';
    msgRetrFileErr    = '451 Cannot open file: %s.';
    msgAborOk         = '225 ABOR command successful.';
    msgTimeout        = '421 Connection closed, timed out after %d secs.';

    msgNotAllowed     = '421 Connection not allowed.';

procedure register;
begin
RegisterComponents('ira Mtp', [TMtpServer]);
end;



function atosi(const value : String) : Integer;
var
    i, j : Integer;
begin
    Result := 0;
    i := 1;
    while (i <= Length(Value)) and (Value[i] = ' ') do
        i := i + 1;
    j := i;
    while (i <= Length(Value)) and ((Value[i] = '+') or (Value[i] = '-')) do
       i := i + 1;
    while (i <= Length(Value)) and (Value[i] >= '0') and (Value[i] <= '9')do begin
        Result := Result * 10 + ord(Value[i]) - ord('0');
        i := i + 1;
    end;
    if j < Length(Value) then begin
        if value[j] = '-' then
            Result := -Result;
    end;
end;


procedure TMtpServer.CreateSocket;
begin
    FSocketServer := TWSocketServer.Create(Self);
end;



constructor TMtpServer.Create(AOwner: TComponent);
var
    Len : Cardinal;
begin
    inherited Create(AOwner);
    AllocateHWnd;

    FClientClass          := TMtpCtrlSocket;
    //FSocketServer         := TWSocketServer.Create(Self);
    CreateSocket;
    FSocketServer.Name    := 'WSocketServer';
    FSocketServer.ClientClass         := FClientClass;
    FSocketServer.OnClientConnect     := ServerClientConnect;
    FSocketServer.OnClientDisconnect  := ServerClientDisconnect;

    FPort               := 'ftp';
    FSocketFamily       := DefaultSocketFamily;
    FAddr               := ICS_ANY_HOST_V4;
    FListenBackLog      := 5;
    FTimeoutSecsLogin   := 60;
    FTimeoutSecsIdle    := 300;
    FTimeoutSecsXfer    := 60;
    FAlloExtraSpace     := 1000000;
    FEventTimer         := TIcsTimer.Create(Self);
    FEventTimer.Enabled := false;
    FEventTimer.OnTimer := EventTimerOnTimer;
    FEventTimer.Interval := 5000;
    FMaxAttempts        := 12 ;
    FBindFtpData        := True;

    SetLength(FCmdTable, 5 + 1 + 5);
    AddCommand('PORT', CommandPORT);
    AddCommand('STOR', CommandSTOR);
    AddCommand('RETR', CommandRETR);
    AddCommand('QUIT', CommandQUIT);
    AddCommand('ABOR', CommandABOR);
end;



destructor TMtpServer.Destroy;
begin
    if Assigned(FEventTimer) then begin
        FEventTimer.Destroy;
        FEventTimer := nil;
    end;
    if Assigned(FSocketServer) then begin
        FSocketServer.Destroy;
        FSocketServer := nil;
    end;
    SetLength(FCmdTable, 0);
    inherited Destroy;
end;



function TMtpServer.MsgHandlersCount : Integer;
begin
    Result := 5 + inherited MsgHandlersCount;
end;



procedure TMtpServer.AllocateMsgHandlers;
begin
    inherited AllocateMsgHandlers;
    FMsg_WM_FTPSRV_CLOSE_REQUEST  := FWndHandler.AllocateMsgHandler(Self);
    FMsg_WM_FTPSRV_ABORT_TRANSFER := FWndHandler.AllocateMsgHandler(Self);
    FMsg_WM_FTPSRV_CLOSE_DATA     := FWndHandler.AllocateMsgHandler(Self);
    FMsg_WM_FTPSRV_START_SEND     := FWndHandler.AllocateMsgHandler(Self);
end;



procedure TMtpServer.FreeMsgHandlers;
begin
    if Assigned(FWndHandler) then begin
        FWndHandler.UnregisterMessage(FMsg_WM_FTPSRV_CLOSE_REQUEST);
        FWndHandler.UnregisterMessage(FMsg_WM_FTPSRV_ABORT_TRANSFER);
        FWndHandler.UnregisterMessage(FMsg_WM_FTPSRV_CLOSE_DATA);
        FWndHandler.UnregisterMessage(FMsg_WM_FTPSRV_START_SEND);
    end;
    inherited FreeMsgHandlers;
end;



procedure TMtpServer.WndProc(var MsgRec: TMessage);
begin
    try
        with MsgRec do begin
            if  Msg = FMsg_WM_FTPSRV_CLOSE_REQUEST  then
                WMFtpSrvCloseRequest(MsgRec)
            else if Msg = FMsg_WM_FTPSRV_ABORT_TRANSFER then
                WMFtpSrvAbortTransfer(MsgRec)
            else if Msg = FMsg_WM_FTPSRV_CLOSE_DATA then
                WMFtpSrvCloseData(MsgRec)
            else if Msg = FMsg_WM_FTPSRV_START_SEND then
                WMFtpSrvStartSend(MsgRec)
            else
                inherited WndProc(MsgRec);
        end;
    except
        on E:Exception do
            HandleBackGroundException(E);
    end;
end;



procedure TMtpServer.WMFtpSrvCloseRequest(var msg: TMessage);
var
    Client : TMtpCtrlSocket;
begin
    Client := TMtpCtrlSocket(msg.LParam);
    if FSocketServer.IsClient(Client) then begin
        { Check if client.ID is still the same as when message where posted }
        if WPARAM(Client.ID) = Msg.WParam then begin
            if Client.AllSent then
                Client.Close
            else
                Client.CloseRequest := TRUE;
        end;
    end;
end;



procedure TMtpServer.Notification(AComponent: TComponent; operation: TOperation);
begin
    inherited Notification(AComponent, operation);
    if operation = opRemove then begin
        if AComponent = FSocketServer then
            FSocketServer := nil;
    end;
end;



function TMtpServer.OpenMemoryStream ( ): TMemoryStream;
begin
    Result := TMemoryStream.Create ; //( MAX_BUFSIZE);
end ;


procedure TMtpServer.CloseMemoryStreams(Client : TMtpCtrlSocket);
begin
    if Client.HasOpenedFile then begin
        if Assigned(Client.DataStream) then Client.DataStream.Destroy;
        Client.DataStream    := nil;
        Client.HasOpenedFile := FALSE;
    end;
end;


procedure TMtpServer.AddCommand(
    const Keyword : String;
    const Proc    : TFtpSrvCommandProc);
begin
    if FLastCmd > High(FCmdTable) then
        raise FtpServerException.Create('Too many command');
    FCmdTable[FLastCmd].KeyWord := KeyWord;
    FCmdTable[FLastCmd].Proc    := Proc;
    Inc(FLastCmd);
end;



procedure TMtpServer.Start;
begin
    if FSocketServer.State = wsListening then
        Exit;
    FSocketServer.Port              := Port;
    FSocketServer.Proto             := 'tcp';
    FSocketServer.SocketFamily      := FSocketFamily;
    FSocketServer.Addr              := FAddr;
    FSocketServer.ListenBacklog     := FListenBackLog;

    FSocketServer.banner := '';

    FSocketServer.MaxClients        := FMaxClients;
    FSocketServer.OnChangeState     := ServSocketStateChange;
    FSocketServer.ComponentOptions  := [wsoNoReceiveLoop];
    FSocketServer.MultiListen;
    FEventTimer.Enabled := true;
end;



procedure TMtpServer.Stop;
begin
    FEventTimer.Enabled := false;
    FSocketServer.Close;
end;



procedure TMtpServer.DisconnectAll;
begin
    FSocketServer.DisconnectAll;
end;



procedure TMtpServer.Disconnect(Client : TMtpCtrlSocket);
begin
    if NOT FSocketServer.IsClient(Client) then
        raise FtpServerException.Create('Disconnect: Not one of our clients');
    FSocketServer.Disconnect(Client);
end;



function TMtpServer.GetActive : Boolean;
begin
    Result := (FSocketServer.State = wsListening);
end;



procedure TMtpServer.SetActive(newValue : Boolean);
begin
    if newValue then
        Start
    else
        Stop;
end;


procedure TMtpServer.SetClientClass(const NewValue: TMtpCtrlSocketClass);
begin
    if NewValue <> FSocketServer.ClientClass then begin
        FClientClass := NewValue;
        FSocketServer.ClientClass := NewValue;
    end;
end;


procedure TMtpServer.ServSocketStateChange(Sender : TObject; OldState, NewState : TSocketState);
begin
    if csDestroying in ComponentState then
        Exit;
    if NewState = wsListening then
        TriggerServerStart
    else if NewState = wsClosed then
        TriggerServerStop;
end;



procedure TMtpServer.ServerClientConnect(Sender: TObject;
                                Client: TWSocketClient; Error: Word);
var
    MyClient: TMtpCtrlSocket;
begin
    if Error <> 0 then
        raise FtpServerException.Create('Session Available Error - ' +
                                                    GetWinsockErr(Error));
    MyClient := Client as TMtpCtrlSocket;
    MyClient.DataSocket.Name := Name + '_DataWSocket' + IntToStr(MyClient.ID);
    MyClient.OnCommand       := ClientCommand;
    MyClient.OnDataSent      := ClientDataSent;
    MyClient.FtpServer       := Self;

    MyClient.SessIdInfo      := Client.GetPeerAddr + ' [' + IntToStr (Client.CliId) + ']' ;
    MyClient.FLastCommand    := 0;
    MyClient.FCommandCount   := 0;


    MyClient.FFtpState       := ftpcWaitingUserCode; // ftpcReady;
end;



procedure TMtpServer.SendAnswer(Client : TMtpCtrlSocket; Answer : TFtpString);
begin
    try
         Client.ReqDurMilliSecs := IcsElapsedMsecs (Client.ReqStartTick);
         TriggerSendAnswer(Client, Answer);

        Client.SendAnswer(Answer);
    except
    end;
end;



procedure TMtpServer.ClientCommand(Sender : TObject; CmdBuf : PAnsiChar; CmdLen : Integer);
const
    TELNET_IAC       = #255;
    TELNET_IP        = #244;
    TELNET_DATA_MARK = #242;
var
    Client  : TMtpCtrlSocket;
    Answer  : TFtpString;
    Params  : TFtpString;
    KeyWord : TFtpString;
    I       : Integer;
    RawParams: RawByteString;
begin
    Client := Sender as TMtpCtrlSocket;
    Answer := '';

    try
        Client.ReqStartTick := IcsGetTickCountX;
        Client.ReqDurMilliSecs := 0;
        RawParams := '';
        I      := 0;
        while I < CmdLen do begin
            if CmdBuf[I] <> TELNET_IAC then begin
                RawParams := RawParams + CmdBuf[I];
                Inc(I);
            end
            else begin
                Inc(I);
                if CmdBuf[I] = TELNET_IAC then
                    RawParams := RawParams + CmdBuf[I];
                Inc(I);
            end;
        end;
            Params := RawParams;

        I := 1;
        KeyWord := UpperCase(ScanGetAsciiArg (Params, I));
        ScanFindArg (Params, I);

        Params := Copy(Params, I, Length(Params));

        TriggerClientCommand(Client, Keyword, Params, Answer);
        if Answer <> '' then begin
            SendAnswer(Client, Answer);
            Exit;
        end;

        if Keyword = '' then begin
            SendAnswer(Client, Format(msgCmdUnknown, [Params]));
            Exit;
        end;

        I := 0;
        while I <= High(FCmdTable) do begin
            if FCmdTable[I].KeyWord = KeyWord then begin
                if I <> ftpcABOR then   { AG V8.02 }
                    Client.CurCmdType := I;
                Client.AnswerDelayed := FALSE;
                FCmdTable[I].Proc(Client, KeyWord, Params, Answer);
                if not Client.AnswerDelayed then
                            SendAnswer(Client, Answer);
                Exit;
            end;
            Inc(I);
        end;
        SendAnswer(Client, Format(msgCmdUnknown, [KeyWord]));
    except
        on E:Exception do begin
            SendAnswer(Client, '501 ' + E.Message);
        end;
    end;
end;



procedure TMtpServer.ClientDataSent(Sender : TObject; AError  : Word);
var
    Client  : TMtpCtrlSocket;
begin
    Client := Sender as TMtpCtrlSocket;
    if Client.CloseRequest then begin
        PostMessage(Handle, FMsg_WM_FTPSRV_CLOSE_REQUEST,
                    WPARAM(Client.ID), LPARAM(Client));
    end;
end;



procedure TMtpServer.ServerClientDisconnect(Sender: TObject; Client: TWSocketClient; Error: Word);
var
    MyClient: TMtpCtrlSocket;
begin
    try
        MyClient := Client as TMtpCtrlSocket;
        if MyClient.DataSocket.State = wsConnected then begin
            MyClient.TransferError    := 'ABORT on Disconnect';
            MyClient.AbortingTransfer := TRUE;
            MyClient.DataSocket.Close;
        end;
        CloseMemoryStreams(MyClient);
        TriggerClientDisconnect(MyClient, Error);
    except
    end;
end;


procedure TMtpServer.WMFtpSrvAbortTransfer(var msg: TMessage);
var
    Client : TMtpCtrlSocket;
    Data   : TWSocket;
begin
    Client := TMtpCtrlSocket(Msg.LParam);
    if FSocketServer.IsClient(Client) then begin
        if WPARAM(Client.ID) = Msg.WParam then begin
            Data := Client.DataSocket;

            if Assigned(Data) then begin

                Data.ShutDown(2);
                Data.Close;
            end;
            Client.DataStream.position:=0;
        end;
    end;
end;



procedure TMtpServer.WMFtpSrvCloseData(var msg: TMessage);
var
    Client : TMtpCtrlSocket;
    Data   : TWSocket;
begin
    Client := TMtpCtrlSocket(Msg.LParam);
    if FSocketServer.IsClient(Client) then begin
        { Check if client.ID is still the same as when message where posted }
        if WPARAM(Client.ID) = Msg.WParam then begin
            Data := Client.DataSocket;
            if Assigned(Data) then begin
                Data.ShutDown(1);    {  Wilfried 24/02/04 }
            end;
           Client.DataStream.position:=0;
        end;
    end;
end;



function TMtpServer.GetClient(nIndex : Integer) : TMtpCtrlSocket;
begin
    Result := FSocketServer.Client [nIndex] as TMtpCtrlSocket;
end;



function TMtpServer.IsClient(SomeThing : TObject) : Boolean;
begin
    Result := FSocketServer.IsClient(Something);
end;



function TMtpServer.GetClientCount : Integer;
begin
    Result := FSocketServer.ClientCount;
end;



procedure TMtpServer.TriggerServerStart;
begin
    if Assigned(FOnStart) then
        FOnStart(Self);
end;



procedure TMtpServer.TriggerServerStop;
begin
    if Assigned(FOnStop) then
        FOnStop(Self);
end;



procedure TMtpServer.TriggerSendAnswer(Client : TMtpCtrlSocket; var Answer : TFtpString);
begin
    if Assigned(FOnAnswerToClient) then
        FOnAnswerToClient(Self, Client, Answer);
end;



procedure TMtpServer.TriggerClientDisconnect(Client : TMtpCtrlSocket; AError  : Word);
begin
    if Assigned(FOnClientDisconnect) then
        FOnClientDisconnect(Self, Client, AError);
end;



procedure TMtpServer.TriggerClientConnect(Client : TMtpCtrlSocket; AError  : Word);
begin
    if Assigned(FOnClientConnect) then
        FOnClientConnect(Self, Client, AError);
end;



procedure TMtpServer.TriggerStorSessionConnected(Client : TMtpCtrlSocket; Data : TWSocket; AError  : Word);
begin
    if Assigned(FOnStorSessionConnected) then
        FOnStorSessionConnected(Self, Client, Data, AError);
end;



procedure TMtpServer.TriggerRetrSessionConnected(Client : TMtpCtrlSocket; Data : TWSocket; AError  : Word);
begin
    if Assigned(FOnRetrSessionConnected) then
        FOnRetrSessionConnected(Self, Client, Data, AError);
end;



procedure TMtpServer.TriggerStorSessionClosed( Client : TMtpCtrlSocket; Data : TWSocket; AError  : Word);
begin
    if Assigned(FOnStorSessionClosed) then
        FOnStorSessionClosed(Self, Client, Data, AError);
end;



procedure TMtpServer.TriggerRetrSessionClosed(Client : TMtpCtrlSocket; Data : TWSocket; AError  : Word);
begin
    if Assigned(FOnRetrSessionClosed) then
        FOnRetrSessionClosed(Self, Client, Data, AError);
end;



procedure TMtpServer.TriggerClientCommand(
    Client      : TMtpCtrlSocket;
    var Keyword : TFtpString;
    var Params  : TFtpString;
    var Answer  : TFtpString);
begin
    if Assigned(FOnClientCommand) then
        FOnClientCommand(Self, Client, KeyWord, Params, Answer);
end;




procedure TMtpServer.TriggerStorDataAvailable(
    Client : TMtpCtrlSocket;
    Data   : TWSocket;
    Buf    : PAnsiChar;
    Len    : LongInt;
    AError : Word);
begin
    if Assigned(FOnStorDataAvailable) then
        FOnStorDataAvailable(Self, Client, Data, Buf, Len, AError);
end;



procedure TMtpServer.TriggerRetrDataSent(
    Client : TMtpCtrlSocket;
    Data   : TWSocket;
    AError : Word);
begin
    if Assigned(FOnRetrDataSent) then
        FOnRetrDataSent(Self, Client, Data, AError);
end;





procedure TMtpServer.TriggerEnterSecurityContext(Client : TMtpCtrlSocket);
begin
    if Assigned(FOnEnterSecurityContext) then
        FOnEnterSecurityContext(Self, Client);
end;



procedure TMtpServer.TriggerLeaveSecurityContext( Client : TMtpCtrlSocket);
begin
    if Assigned(FOnLeaveSecurityContext) then
        FOnLeaveSecurityContext(Self, Client);
end;



procedure TMtpServer.TriggerTimeout( Client: TMtpCtrlSocket; Duration: Integer; var Abort   : Boolean);
begin
    if Assigned(FOnTimeout) then
        FOnTimeout(Self, Client, Duration, Abort);
end;



procedure TMtpServer.TriggerDisplay(Client : TMtpCtrlSocket; Msg: TFtpString);
begin
    if Assigned(FOnDisplay) then
        FOnDisplay(Self, Client, Msg);
end;







procedure TMtpServer.CommandQUIT(Client: TMtpCtrlSocket; var Keyword : TFtpString; var Params  : TFtpString; var Answer  : TFtpString);
begin
    Client.CurCmdType := ftpcQUIT;
    Answer            := msgQuit;
    PostMessage(Handle, FMsg_WM_FTPSRV_CLOSE_REQUEST,
                WPARAM(Client.ID), LPARAM(Client));
end;



function GetInteger(var I : Integer; const Src : String) : LongInt;
begin
    while (I <= Length(Src)) and IsSpace(Src[I]) do
        Inc(I);
    Result := 0;
    while (I <= Length(Src)) and IsDigit(Src[I]) do begin
        Result := Result * 10 + Ord(Src[I]) - Ord('0');
        Inc(I);
    end;
    { Skip trailing white spaces }
    while (I <= Length(Src)) and IsSpace(Src[I]) do
        Inc(I);

    if I <= Length(Src) then begin
        if Src[I] = ',' then
            Inc(I)
        else
            raise FtpServerException.Create('GetInteger: unexpected char');
    end;
end;



procedure TMtpServer.CommandPORT(Client: TMtpCtrlSocket; var Keyword : TFtpString; var Params  : TFtpString; var Answer  : TFtpString);
var
    I : Integer;
    N : LongInt;
begin
    try
        Client.CurCmdType := ftpcPORT;
        I                 := 1;
        Client.DataAddr   := IntToStr(GetInteger(I, Params));
        Client.DataAddr   := Client.DataAddr + '.' + IntToStr(GetInteger(I, Params));
        Client.DataAddr   := Client.DataAddr + '.' + IntToStr(GetInteger(I, Params));
        Client.DataAddr   := Client.DataAddr + '.' + IntToStr(GetInteger(I, Params));
        N := GetInteger(I, Params);
        N := (N shl 8) + GetInteger(I, Params);
        Client.DataPort := IcsIntToStrA(N);
        Answer := msgPortSuccess;
    except
        Answer := msgPortFailed;
    end;
end;



procedure TMtpServer.CommandSTOR(Client: TMtpCtrlSocket; var Keyword : TFtpString; var Params  : TFtpString; var Answer  : TFtpString);
var
    Allowed  : Boolean;
    FilePath : TFtpString;
    n: Integer;
begin
    try
        if Client.FtpState <> ftpcWaitingUserCode then begin
            Answer := 'not ftpcWaitingUserCode';
            Exit;
        end;
        if Params = '' then begin
            Answer := Format(msgStorFailed, ['Size not specified']);
            Exit;
        end
        else


          n:= Pos ( ' ', Params , 1);
          if n = 0 then begin
              Answer := 'MemoryName not specified';
              Exit;
          end;


          Client.StreamSize := StrToIntDef( LeftStr ( Params,n-1)  , 0);
          Client.MemoryName := rightStr ( Params , length(params) - n ) ;
          if Assigned(Client.DataStream ) then  begin

            Client.DataStream.SetSize( Client.StreamSize) ;
            Client.DataStream.Position :=0;
          end;

        try
            Client.CurCmdType       := ftpcSTOR;
            //Client.MemoryName         := Client.PeerAddr ;
            Client.HasOpenedFile    := FALSE;
            Allowed := True;
            PrepareStorDataSocket(Client);     // <--- connect al client
            Answer := Format(msgStorSuccess, [Params]);
        except
            on E:Exception do begin
                Answer := Format(msgStorFailed, [E.Message]);
            end;
        end;
    finally
    end;
end;



procedure TMtpServer.PrepareStorDataSocket(Client : TMtpCtrlSocket);
begin
    Client.AbortingTransfer := FALSE;
    Client.TransferError    := 'Transfer Ok';

        Client.DataSocket.Proto               := 'tcp';
        Client.DataSocket.Addr                := Client.DataAddr;
        Client.DataSocket.Port                := Client.DataPort;
        Client.DataSocket.OnSessionConnected  := ClientStorSessionConnected;
        Client.DataSocket.OnSessionClosed     := ClientStorSessionClosed;
        Client.DataSocket.OnDataAvailable     := ClientStorDataAvailable;
        Client.DataSocket.OnDataSent          := nil;
        Client.DataSocket.LingerOnOff         := wsLingerOff;
        Client.DataSocket.LingerTimeout       := 0;
        if FBindFtpData then begin
            Client.DataSocket.LocalAddr           := Client.GetXAddr;
            Client.DataSocket.LocalPort           := 'ftp-data'; {20}
        end;
        Client.DataSocket.ComponentOptions    := [wsoNoReceiveLoop];
        Client.DataSocket.Connect;
        if Client.DataSocket.SocketRcvBufSize <> Client.FRcvBufSize then
           Client.DataSocket.SocketRcvBufSize := Client.FRcvBufSize;
end;




procedure TMtpServer.ClientStorSessionConnected(Sender : TObject; AError  : Word);
var
    Client      : TMtpCtrlSocket;
    Data        : TWSocket;
begin

    Data                     := TWSocket(Sender);
    Client                   := TMtpCtrlSocket(Data.Owner);
    Client.DataSessionActive := TRUE;
    Client.ByteCount := 0;
    Client.TotPutBytes :=0; // ogni volta inizia da 0.
    if Assigned (Client.DataStream) then begin
      Client.DataStream.SetSize(Client.StreamSize );
      Client.DataStream.Position :=0;
    end;

    Client.XferStartTick := IcsGetTickCountX;
    Client.LastTick := IcsGetTickCountX;

    if Client.AbortingTransfer then
        Exit;
    TriggerStorSessionConnected(Client, Data, AError);
end;



procedure TMtpServer.ClientStorSessionClosed(Sender : TObject; AError  : Word);
var
    Client      : TMtpCtrlSocket;
    Data        : TWSocket;
    Duration    : Integer;
    S           : String;
    BytesSec    : Int64;
    Answer      : String;
begin
    Data                     := TWSocket(Sender);
    Client                   := TMtpCtrlSocket(Data.Owner);

    Client.DataSessionActive := FALSE;
    Client.RestartPos        := 0;
    Client.DataPort          := 'ftp-data';

    if Assigned(FOnDisplay) then begin
        Duration := IcsElapsedMsecs (Client.XferStartTick);
        S := Client.MemoryName + ' ' +
                IntToKbyte(Client.ByteCount) + 'bytes received in ';
        if Duration < 2000 then
            S := S + IntToStr(Duration) + ' milliseconds'
        else begin
            S := S + IntToStr(Duration div 1000) + ' seconds';
            if Client.ByteCount > 32767 then
                BytesSec := 1000 * (Client.ByteCount div Duration)
            else
                BytesSec := (1000 * Client.ByteCount) div Duration;
            S := S + ' (' + IntToKbyte(BytesSec) + 'bytes/sec)';
        end;
        TriggerDisplay (Client, S);
    end;

    if Client.AbortingTransfer and (Client.TransferError = '') then
        Exit;

    Answer := '';
    case Client.CurCmdType of
    ftpcSTOR :
        begin
            if Client.AbortingTransfer then
                Answer := Format(msgStorAborted, [Client.TransferError])
            else if AError = 0 then
                Answer := msgStorOk + ':' + Client.memoryName
            else
                Answer := Format(msgStorError, [GetWinsockErr(AError)]);
        end;
    else
        raise Exception.Create('Program error in ClientStorSessionClosed');
        exit;
    end;

    Client.DataStream.position:=0;
    TriggerStorSessionClosed(Client, Data, AError);

    SendAnswer(Client, Answer);
end;



procedure TMtpServer.ClientStorDataAvailable(Sender: TObject; AError  : word);
var
    Len    : Integer;
    Client : TMtpCtrlSocket;
    Data   : TWSocket;
    NewPos : TFtpBigInt;
begin
    Data   := TWSocket(Sender);
    Client := TMtpCtrlSocket(Data.Owner);
    Len    := Data.Receive(Client.RcvBuf, Client.RcvSize);
    if Len <= 0 then
        Exit;

    if Client.AbortingTransfer then
        Exit;
    Client.LastTick := IcsGetTickCountX;

    try
        TriggerStorDataAvailable(Client, Data, Client.RcvBuf, Len, AError);

        if (not Client.HasOpenedFile) and  (not Assigned(Client.DataStream)) then begin
            TriggerEnterSecurityContext(Client);
            try
                Client.DataStream := OpenMemoryStream(  );
            finally
                TriggerLeaveSecurityContext(Client);
            end;
            NewPos := 0;
        Client.HasOpenedFile := TRUE;
        end;

        if Assigned(Client.DataStream) then begin
            Client.ByteCount := Client.ByteCount + Len;
            Client.TotPutBytes := Client.TotPutBytes + Len;
            TriggerEnterSecurityContext(Client);
            try
//                CopyMemory ( DirectMemoryPtr^, Client.RcvBuf^, Len);
                Client.DataStream.WriteBuffer(Client.RcvBuf^, Len);
            finally
                TriggerLeaveSecurityContext(Client);
            end;
        end;
    except
        on E:Exception do begin
            Client.TransferError    := E.Message;
            Client.AbortingTransfer := TRUE;
            PostMessage(Handle, FMsg_WM_FTPSRV_ABORT_TRANSFER,
                        WPARAM(Client.ID), LPARAM(Client));
        end;
    end;
end;




procedure TMtpServer.CommandRETR( Client: TMtpCtrlSocket; var Keyword : TFtpString; var Params  : TFtpString; var Answer  : TFtpString);
var
    Allowed     : Boolean;
    FilePath    : TFtpString;
    DelayedSend : Boolean;
begin
    try
        if Client.FtpState <> ftpcWaitingUserCode then begin
            Answer := 'ftpcWaitingUserCode';
            Exit;
        end;



        try
            Client.CurCmdType    := ftpcRETR;
            Client.HasOpenedFile := FALSE;
            Client.MemoryName    := Params;
            Allowed := True;

            Client.MemoryName := Client.peeraddr;  ;

            Answer := msgRetrSuccess + IntToStr(Client.DataStream.Size  ) ;
            DelayedSend     := FALSE;
            if Assigned(FOnGetProcessing) then
                FOnGetProcessing(Self, Client, DelayedSend);
            if not DelayedSend then
                DoStartSendData(Client, Answer);
        except
            on E:Exception do begin
                Answer := Format(msgRetrFailed, [E.Message]);
            end;
        end;
    finally
    end;
end;



procedure TMtpServer.DoStartSendData(Client : TMtpCtrlSocket; var Answer : TFtpString);
var
    NewPos  : TFtpBigInt;
    FileExt : String;
    Done    : Boolean;
    FreeSpace: Int64;
begin
    try
        if (not Assigned(Client.DataStream)) then begin
            Answer := Format(msgRetrFailed, ['Failed to open local stream']);
            Exit;
        end;
        Client.LastTick := IcsGetTickCountX;

        PostMessage(Handle, FMsg_WM_FTPSRV_START_SEND, 0, LPARAM(Client));
    except
        on E: Exception do begin
            Answer := Format(msgRetrFailed, [E.Message]);
            ClosememoryStreams(Client);
            Exit;
        end;
    end;
end;



procedure TMtpServer.WMFtpSrvStartSend(var msg: TMessage);
var
    Client      : TMtpCtrlSocket;
begin
    Client := TObject(Msg.LParam) as TMtpCtrlSocket;
    StartSendData(Client);
end;




procedure TMtpServer.StartSendData(Client : TMtpCtrlSocket);
begin
    Client.AbortingTransfer              := FALSE;
    Client.DataSent                      := FALSE;
    Client.TransferError                 := 'Transfer Ok';
        Client.DataSocket.Close;
        Client.DataSocket.Proto              := 'tcp';
        Client.DataSocket.Addr               := Client.DataAddr;
        Client.DataSocket.Port               := Client.DataPort;
        Client.DataSocket.OnSessionConnected := ClientRetrSessionConnected;
        Client.DataSocket.OnSessionClosed    := ClientRetrSessionClosed;
        Client.DataSocket.OnDataAvailable    := nil;
        Client.DataSocket.OnDataSent         := ClientRetrDataSent;
        Client.DataSocket.LingerOnOff        := wsLingerOff;
        Client.DataSocket.LingerTimeout      := 0;
        if FBindFtpData then begin
            Client.DataSocket.LocalAddr           := Client.GetXAddr;
            Client.DataSocket.LocalPort           := 'ftp-data'; {20}
        end;
        Client.DataSocket.ComponentOptions    := [wsoNoReceiveLoop];

        Client.DataSocket.Connect;
        if Client.DataSocket.SocketSndBufSize <> Client.FSndBufSize then
            Client.DataSocket.SocketSndBufSize := Client.FSndBufSize;
end;





procedure TMtpServer.ClientRetrSessionConnected(Sender : TObject; AError  : Word);
var
    Client      : TMtpCtrlSocket;
    Data        : TWSocket;
begin
    Data                     := TWSocket(Sender);
    Client                   := TMtpCtrlSocket(Data.Owner);
    Client.DataSessionActive := (AError = 0);

    if Client.AbortingTransfer then
        Exit;

    try
        TriggerRetrSessionConnected(Client, Data, AError);
        if AError <> 0 then
        begin
            raise FtpServerException.Create('Client data socket connection Error - ' +
               GetWinsockErr(AError) + ' - ' + Client.DataAddr + ':' + Client.DataPort);
        end;
    except
        on E: Exception do begin
            Client.AbortingTransfer := TRUE;
            Client.TransferError    := E.Message;
            PostMessage(Handle, FMsg_WM_FTPSRV_ABORT_TRANSFER,
                        WPARAM(Client.ID), LPARAM(Client));
            Exit;
        end;
    end;

    Client.ByteCount := 0;
    Client.TotGetBytes :=0; // ogni volta inizia da 0.
    Client.XferStartTick := IcsGetTickCountX;
    Client.LastTick := IcsGetTickCountX;
    SendNextDataChunk(Client, Data);
end;



procedure TMtpServer.ClientRetrSessionClosed(Sender : TObject; AError  : Word);
var
    Client      : TMtpCtrlSocket;
    Data        : TWSocket;
    Duration    : Integer;
    S           : String;
    BytesSec    : Int64;
begin
    Data                     := TWSocket(Sender);
    Client                   := TMtpCtrlSocket(Data.Owner);


    Client.DataSessionActive := FALSE;
    Client.RestartPos        := 0;

    Client.DataPort          := 'ftp-data';

    // qui non dobbiamo chiudere lo stream. semplicemente proseguire.
    if Assigned(FOnDisplay) then begin
        Duration := IcsElapsedMsecs (Client.XferStartTick);
        S := Client.MemoryName;
        if S = '' then S := 'Directory';
        S := S + ' ' + IntToKbyte(Client.ByteCount) + 'bytes sent in ';
        if Duration < 2000 then
            S := S + IntToStr(Duration) + ' milliseconds'
        else begin
            S := S + IntToStr(Duration div 1000) + ' seconds';
            if Client.ByteCount > 32767 then
                BytesSec := 1000 * (Client.ByteCount div Duration)
            else
                BytesSec := (1000 * Client.ByteCount) div Duration;
            S := S + ' (' + IntToKbyte(BytesSec) + 'bytes/sec)';
        end;
        TriggerDisplay (Client, S);
    end;

    if Client.AbortingTransfer and (Client.TransferError = '') then
        Exit;

    if Client.AbortingTransfer then
        SendAnswer(Client, Format(msgRetrFailed, [Client.TransferError]))
    else if AError <> 0 then
        SendAnswer(Client, Format(msgRetrFailed, ['Error - ' + GetWinsockErr(AError)]))
    else
        SendAnswer(Client, msgRetrOk );

    TriggerRetrSessionClosed(Client, Data, AError);
end;



procedure TMtpServer.SendNextDataChunk(Client : TMtpCtrlSocket; Data: TWSocket);
var
    Count : LongInt;
begin
    try
        Count := 0;
        TriggerEnterSecurityContext(Client);
        try

          begin
                if Assigned(Client.DataStream) then
                    Count := Client.DataStream.Read(Client.RcvBuf^, Client.RcvSize);
            end;
        finally
            TriggerLeaveSecurityContext(Client);
        end;
        Client.LastTick := IcsGetTickCountX;

        if Count > 0 then begin
            Client.ByteCount := Client.ByteCount + Count;
            Client.TotGetBytes := Client.TotGetBytes + Count;
            Data.Send(Client.RcvBuf, Count);
        end
        else begin
            if not Client.DataSent then begin
                Client.DataSent := TRUE;
                PostMessage(Handle, FMsg_WM_FTPSRV_CLOSE_DATA,
                            WPARAM(Client.ID), LPARAM(Client));
            end;
        end;
    except
        on E:Exception do begin
            Client.TransferError    := E.Message;
            Client.AbortingTransfer := TRUE;
            PostMessage(Handle, FMsg_WM_FTPSRV_ABORT_TRANSFER,
                        WPARAM(Client.ID), LPARAM(Client));
        end;
    end;
end;



procedure TMtpServer.ClientRetrDataSent(Sender : TObject; AError : Word);
var
    Client : TMtpCtrlSocket;
    Data   : TWSocket;
begin
    Data   := TWSocket(Sender);
    Client := TMtpCtrlSocket(Data.Owner);

    if Client.AbortingTransfer then
        Exit;

    try
        TriggerRetrDataSent(Client, Data, AError);
        if AError <> 0 then
            raise FtpServerException.Create('Send Error - ' + GetWinsockErr(AError));
        SendNextDataChunk(Client, Data);
    except
        on E:Exception do begin
            Client.TransferError    := E.Message;
            Client.AbortingTransfer := TRUE;
            SendAnswer(Client, Format(msgRetrAborted, [Client.TransferError]));
            PostMessage(Handle, FMsg_WM_FTPSRV_ABORT_TRANSFER,
                        WPARAM(Client.ID), LPARAM(Client));
        end;
    end;
end;





procedure TMtpServer.CommandABOR(
    Client      : TMtpCtrlSocket;
    var Keyword : TFtpString;
    var Params  : TFtpString;
    var Answer  : TFtpString);
begin
    if Client.DataSocket.State = wsConnected then begin
        Client.TransferError    := 'ABORT requested by client';
        Client.AbortingTransfer := TRUE;
        Client.DataSocket.Close;
    end;
    Answer := msgAborOk;
end;





{$IFDEF NOFORMS}
function FtpSrvWindowProc(
    ahWnd   : HWND;
    auMsg   : Integer;
    awParam : WPARAM;
    alParam : LPARAM): Integer; stdcall;
var
    Obj    : TObject;
    MsgRec : TMessage;
begin
    Obj := TObject(GetWindowLong(ahWnd, 0));

    if not (Obj is Tftpserver) then
        Result := DefWindowProc(ahWnd, auMsg, awParam, alParam)
    else begin
        MsgRec.Msg    := auMsg;
        MsgRec.wParam := awParam;
        MsgRec.lParam := alParam;

        TFtpServer(Obj).WndProc(MsgRec);
        Result := MsgRec.Result;
    end;
end;
{$ENDIF}



function TMtpServer.GetMultiListenIndex: Integer;
begin
  if Assigned(FSocketServer) then
        Result := FSocketServer.MultiListenIndex
    else
        Result := -1;
end;



function TMtpServer.GetMultiListenSockets: TWSocketMultiListenCollection;
begin
    if Assigned(FSocketServer) then
        Result := FSocketServer.MultiListenSockets
    else
        Result := nil;
end;



procedure TMtpServer.SetMultiListenSockets(  const Value: TWSocketMultiListenCollection);
begin
    if Assigned(FSocketServer) then
        FSocketServer.MultiListenSockets := Value;
end;



procedure TMtpServer.SetOnBgException(const Value: TIcsBgExceptionEvent);
begin
    if Assigned(FSocketServer) then
        FSocketServer.OnBgException := Value;
    inherited;
end;



procedure TMtpServer.ClientProcessingThreadTerminate(Sender: TObject);
var
    Answer    : TFtpString;
    AThread   : TClientProcessingThread;
    Params    : TFtpString;
    Data      : TWSocket;
begin
    AThread := TClientProcessingThread(Sender);
    if IsClient(AThread.Client) and
       (AThread.Client.ID = AThread.ClientID) then begin
        AThread.Client.ProcessingThread := nil;
        if AThread.Client.State <> wsConnected then
            Exit;

        AThread.Client.LastTick := IcsGetTickCountX;
            Answer := Format('500 Executing command %s failed', [AThread.Keyword]);
        AThread.Client.AnswerDelayed := FALSE;
        SendAnswer(AThread.Client, Answer);
    end;
end;


procedure TMtpServer.EventTimerOnTimer (Sender : TObject);
var
    Client   : TMtpCtrlSocket;
    I        : integer;
    Timeout  : integer;
    Duration : integer;
    Abort    : boolean ;
    CurTicks : LongWord;
begin
    FEventTimer.Enabled := false;
    try
        if FSocketServer.ClientCount = 0 then exit;
        CurTicks := IcsGetTickCountX;
        for I := 0 to Pred (FSocketServer.ClientCount) do begin
            Client := FSocketServer.Client[I] as TMtpCtrlSocket;
            if Client.FSessionClosedFlag then Continue;



            Timeout := 0;
            case Client.FtpState of
                ftpcWaitingUserCode: Timeout := FTimeoutSecsLogin;
                ftpcReady, ftpcWaitingAnswer: Timeout := FTimeoutSecsIdle;
            end;
            if Client.DataSocket.State = wsConnected then begin
                if FTimeoutSecsXfer < FTimeoutSecsIdle then Timeout := FTimeoutSecsXfer;
            end;
            if Timeout > 0 then begin
                Duration :=  IcsDiffTicks(Client.LastTick, CurTicks) div TicksPerSecond;
                if Duration >= Timeout then begin
                    Abort := true;
                    TriggerTimeout(Client, Duration, Abort);
                    if NOT Abort then
                        Client.LastTick := IcsGetTickCountX
                    else begin

                        if Client.DataSocket.State = wsConnected then begin
                            Client.TransferError    := 'ABORT on Timeout';
                            Client.AbortingTransfer := TRUE;
                            Client.DataSocket.Close;
                        end
                        else begin
                            SendAnswer(Client, WideFormat(msgTimeout, [Duration]));

                            Client.Close;
                        end;
                    end;
                end;
            end;
        end;
    finally
        FEventTimer.Enabled := true;
    end ;
end;



constructor TMtpCtrlSocket.Create(AOwner: TComponent);
begin
    inherited Create(AOwner);
    FDataSocket      := TWSocket.Create(Self);
    FDataSocket.Name := 'DataWSocket';
    FFtpState        := ftpcInvalid;
    SetRcvSize(DefaultRcvSize);
    LastTick         := IcsGetTickCountX;
    SessStartTick    := IcsGetTickCountX;
    ReqStartTick     := 0;
    ReqDurMilliSecs  := 0;
    TotGetBytes      := 0;
    TotPutBytes      := 0;
    FailedAttempts   := 0;
    DelayAnswerTick  := TriggerDisabled;
    FSndBufSize      := DefaultRcvSize;
    FRcvBufSize      := DefaultRcvSize;
end;



destructor TMtpCtrlSocket.Destroy;
begin
    FRcvCnt := 0;
    SetRcvSize(0);
    if Assigned(ProcessingThread) then begin
        ProcessingThread.OnTerminate := nil;
        FreeAndNil(ProcessingThread);
    end;
    if Assigned(FDataSocket) then begin
        FDataSocket.Destroy;
        FDataSocket := nil;
    end;
    inherited Destroy;
end;



procedure TMtpCtrlSocket.SetRcvSize(newValue : Integer);
begin
    if FRcvCnt <> 0 then
        raise EFtpCtrlSocketException.Create('Data in buffer, can''t change size');

    if FRcvSize < 0 then
        FRcvSize := 0;

    if FRcvSize = newValue then
        Exit;

    if FRcvBuf <> nil then begin
        FreeMem(FRcvBuf, FRcvSize);
        FRcvBuf := nil;
    end;

    FRcvSize := newValue;

    if newValue > 0 then
        GetMem(FRcvBuf, FRcvSize);
end;



procedure TMtpCtrlSocket.SetRcvBufSize(newValue : Integer);
begin
    if newValue < 1024 then
        FRcvBufSize := 1024
    else
        FRcvBufSize := newValue;
end;



procedure TMtpCtrlSocket.SetSndBufSize(newValue : Integer);
begin
    if newValue < 1024 then
        FSndBufSize := 1024
    else
        FSndBufSize := newValue;
end;


procedure TMtpCtrlSocket.SetStreamSize(newValue : Integer);
begin
    if newValue < 1024 then
        FStreamSize := 1024
    else
        FStreamSize := newValue;
end;




procedure TMtpCtrlSocket.SetOnBgException(const Value: TIcsBgExceptionEvent);
begin
    if Assigned(FDataSocket) then
        FDataSocket.OnBgException := Value;
    inherited;
end;




procedure TMtpCtrlSocket.TriggerSessionClosed(Error: Word);
begin
    if Assigned(ProcessingThread) then
        ProcessingThread.Terminate;
    inherited TriggerSessionClosed(Error);
end;



procedure TMtpCtrlSocket.TriggerSessionConnected(Error : Word);
begin
    FPeerAddr := inherited GetPeerAddr;
    inherited TriggerSessionConnected(Error);
end;



procedure TMtpCtrlSocket.TriggerCommand(CmdBuf : PAnsiChar; CmdLen : Integer);
begin
    if Assigned(FOnCommand) then
        FOnCommand(Self as TMtpCtrlSocket, CmdBuf, CmdLen);
end;



function TMtpCtrlSocket.TriggerDataAvailable(Error : Word) : Boolean;
var
    Len  : Integer;
    I    : Integer;
begin
    Result := TRUE;

    Len := Receive(@FRcvBuf[FRcvCnt], FRcvSize - FRcvCnt - 1);
    if Len <= 0 then
        Exit;

    FRcvCnt := FRcvCnt + Len;
    FRcvBuf[FRcvCnt] := #0;
    LastTick := IcsGetTickCountX;
    TotPutBytes := TotPutBytes + Len;

    while TRUE do begin
        I := 0;
        while (I < FRcvCnt) and (FRcvBuf[I] <> #10) do
            Inc(I);
        if I >= FRcvCnt then begin
            if FRcvCnt >= (FRcvSize - 1) then begin
                StrPCopy(FRcvBuf, 'OVER' + #13#10);
                FRcvCnt := StrLen(FRcvBuf);
                I       := FRcvCnt - 1;
            end
            else
                Exit;
        end;
        FRcvBuf[I]   := #0;
        FLastCommand := Now;
        Inc(FCommandCount);
        if (I > 1) and (FRcvBuf[I - 1] = #13) then begin
            FRcvBuf[I - 1] := #0;
            TriggerCommand(FRcvBuf, I - 1);
            FRcvBuf[I - 1] := #13;
        end
        else
            TriggerCommand(FRcvBuf, I);

        FRcvBuf[I] := #10;
        if I >= (FRcvCnt - 1) then begin
            FRcvCnt    := 0;
            FRcvBuf[0] := #0;
            break;
        end;
        Move(FRcvBuf[I + 1], FRcvBuf^, FRcvCnt - I);
        FRcvCnt := FRcvCnt - I - 1;
    end;
end;



procedure TMtpCtrlSocket.SendAnswer(const Answer : RawByteString);
begin
    SendStr(Answer + #13#10);
    LastTick := IcsGetTickCountX;
    TotGetBytes := TotGetBytes + Length (Answer) + 2;
end;



procedure TMtpCtrlSocket.DataStreamWriteString(const Str: UnicodeString; DstCodePage: LongWord);
begin
    StreamWriteString(DataStream, Str, DstCodePage);
end;



procedure TMtpCtrlSocket.DataStreamWriteString(const Str: UnicodeString);
begin
    StreamWriteString(DataStream, Str, CP_ACP);
end;



procedure TMtpCtrlSocket.DataStreamWriteString(const Str: AnsiString);
begin
    DataStream.Write(Pointer(Str)^, Length(Str));
end;



procedure TMtpCtrlSocket.DataStreamWriteString( const Str: AnsiString; DstCodePage: LongWord);
var
    S : AnsiString;
begin
    if DstCodePage = CP_ACP then
        DataStream.Write(Pointer(Str)^, Length(Str))
    else begin
        S := ConvertCodePage(Str, CP_ACP, DstCodePage);
        DataStream.Write(Pointer(S)^, Length(S));
    end;
end;



procedure TMtpCtrlSocket.DataStreamReadString(var Str: AnsiString;
  Len: TFtpBigInt);
var
    ReadLen: Cardinal;
begin
    SetLength(Str, Len);
    ReadLen := DataStream.Read(Pointer(Str)^, Len);
    if ReadLen < Len then
        SetLength(Str, ReadLen);
end;


procedure TMtpCtrlSocket.DataStreamReadString( var Str: AnsiString; Len: TFtpBigInt; SrcCodePage: LongWord);
var
    BytesRead : Cardinal;
    Buf       : PAnsiChar;
    BufW      : PWideChar;
    L1, L2    : Integer;
begin
    SetLength(Str, 0);
    if Len < 0 then Exit;
    if (SrcCodePage = CP_ACP) then
    begin
        SetLength(Str, Len);
        BytesRead := DataStream.Read(Pointer(Str)^, Len);
        if BytesRead < Len then
            SetLength(Str, BytesRead);
    end
    else begin
        GetMem(Buf, Len);
        try
            BytesRead := DataStream.Read(Buf^, Len);
            L1 :=  IcsMbToWc{MultiByteToWideChar}(SrcCodePage, 0, Buf, BytesRead, nil, 0);
            GetMem(BufW, L1 * SizeOf(WideChar));
            try
                IcsMbToWc{MultiByteToWideChar}(SrcCodePage, 0, Buf, BytesRead, BufW, L1);
                L2 := IcsWcToMb{WideCharToMultibyte}(CP_ACP, 0, BufW, L1, nil, 0, nil, nil);
                if L2 <> Len then
                    ReallocMem(Buf, L2);
                L1 := IcsWcToMb{WideCharToMultibyte}(CP_ACP, 0, BufW, L1, Buf, L2, nil, nil);
                SetLength(Str, L1);
                Move(Buf[0], Pointer(Str)^, L1);
            finally
                ReallocMem(BufW, 0);
            end;
        finally
            ReallocMem(Buf, 0);
        end;
    end;
end;



procedure TMtpCtrlSocket.DataStreamReadString(var Str: UnicodeString; Len: TFtpBigInt );
var
    SBuf : array [0..2047] of AnsiChar;
    HBuf : PAnsiChar;
    eLen : Cardinal;
begin
        SetLength(Str, Len);
        eLen := DataStream.Read(Pointer(Str)^, Len * SizeOf(WideChar));
        if (eLen div SizeOf(WideChar)) < Len then
            SetLength(Str, (eLen div SizeOf(WideChar)));
end;

procedure TMtpCtrlSocket.SetAbortingTransfer(newValue : Boolean);
begin
    FAbortingTransfer := newValue;
end;



procedure UpdateThreadOnProgress( Obj: TObject; Count: Int64; var Cancel: Boolean);
begin
    if (Obj is TClientProcessingThread) then
    begin
        Cancel := (Obj as TClientProcessingThread).Terminated;
        (Obj as TClientProcessingThread).Client.LastTick := IcsGetTickCountX;
    end
    else if (Obj is TMtpCtrlSocket) then
    begin
        Cancel := (Obj as TMtpCtrlSocket).AbortingTransfer;
        (Obj as TMtpCtrlSocket).LastTick := IcsGetTickCountX;
    end
end;



procedure TClientProcessingThread.TriggerEnterSecurityContext;
var
    f_EnterSecurityContext : TFtpSecurityContextEvent;
begin
    f_EnterSecurityContext := Client.FtpServer.FOnEnterSecurityContext;
    if Assigned(f_EnterSecurityContext) then
        f_EnterSecurityContext(Client.FtpServer, Client);
end;




procedure TClientProcessingThread.TriggerLeaveSecurityContext;
var
    f_LeaveSecurityContext : TFtpSecurityContextEvent;
begin
    f_LeaveSecurityContext := Client.FtpServer.FOnLeaveSecurityContext;
    if Assigned(f_LeaveSecurityContext) then
        f_LeaveSecurityContext(Client.FtpServer, Client);

end;


procedure TClientProcessingThread.Execute;
var
    NewSize: Int64;
    TotalFiles: integer;
begin
    ClientID := Client.ID;
    try
        with Client.ProcessingThread do begin
            StartTick := IcsGetTickCountX;
            OutData := '';
        end;
    except
        OutData := '';
    end;
end;


end.


