unit iramtpCli;

{$B-}             { Enable partial boolean evaluation   }
{$T-}             { Untyped pointers                    }
{$X+}             { Enable extended syntax              }

interface

uses
    Winapi.Windows,
    Winapi.Messages,
    OverbyteIcsWinSock,
    System.SysUtils,
    System.Classes,
    Vcl.Forms,
    OverbyteIcsWndControl,
    OverbyteIcsWSocket,
    Strutils,

    OverbyteIcsUtils,
    OverByteIcsFtpSrvT;


const

{$IFDEF FTPCLI_BUFFER_OLD}
  FTP_SND_BUF_SIZE = 1460;
  FTP_RCV_BUF_SIZE = 4096;
{$ELSE}
  {$IFDEF FTPCLI_BUFFER_SMALL}
    FTP_SND_BUF_SIZE = 8192;
    FTP_RCV_BUF_SIZE = 8192;
  {$ELSE}
    {$IFDEF FTPCLI_BUFFER_MEDIUM}
      FTP_SND_BUF_SIZE = 16384;
      FTP_RCV_BUF_SIZE = 16384;
    {$ELSE}
      FTP_SND_BUF_SIZE = 32768;
      FTP_RCV_BUF_SIZE = 32768;
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

type
  TFtpOption      = (ftpAcceptLF, ftpWaitUsingSleep);
  TFtpOptions     = set of TFtpOption;
  TFtpState       = (ftpNotConnected,  ftpReady, ftpInternalReady, ftpDnsLookup, ftpConnected, ftpAbort,
                     ftpInternalAbort, ftpWaitingResponse );
  TFtpRequest     = (ftpNone,  ftpOpenAsync, ftpConnectAsync,  ftpReceiveAsync, ftpPortAsync, ftpGetAsync,
                     ftpQuitAsync,  ftpPutAsync, ftpRqAbort,   ftpTransmitAsync   );
  TFtpFct         = (ftpFctNone, ftpFctOpen, ftpFctGet, ftpFctQuit, ftpFctPut, ftpFctPort);
  TFtpFctSet      = set of TFtpFct;

  TFtpDisplay     = procedure(Sender    : TObject; var Msg   : String) of object;
  TFtpProgress64  = procedure(Sender    : TObject; Count     : Int64; var Abort : Boolean) of object;
  TFtpCommand     = procedure(Sender    : TObject; var Cmd   : String) of object;
  TFtpRequestDone = procedure(Sender    : TObject; RqType    : TFtpRequest; ErrCode   : Word) of object;
  TFtpReadyToTransmit = procedure(Sender      : TObject; var bCancel : Boolean) of object;
  TFtpNextProc    = procedure of object;

  FtpException = class(Exception);

  TCustomMtpCli = class(TIcsWndControl)
  protected
    FHostName           : String;
    FPort               : String;
    FSocketFamily       : TSocketFamily;
    FDataPortRangeStart : LongWord;
    FDataPortRangeEnd   : LongWord;
    FLastDataPort       : LongWord;
    FExternalIPv4       : String;
    FDSocketSndBufSize  : Integer;
    FDSocketRcvBufSize  : Integer;
    FLocalAddr          : String;
    FLocalAddr6         : String;
    FDnsResult          : String;
    FType               : Char;
    FProxyServer        : String;
    FProxyPort          : String;
    FAppendFlag         : Boolean;
    FDisplayFileFlag    : Boolean;
    FControlSocket      : TWSocket;
    FDataSocket         : TWSocket;
    FStartTime          : LongInt;
    FStopTime           : LongInt;
    FStreamSize         : LongInt;
    FMemoryPtr          : Pointer ;
    FMemoryName         : String;
    FState              : TFtpState;
    FStatusCode         : LongInt;
    FRequestResult      : Integer;
    FFctSet             : TFtpFctSet;
    FFctPrv             : TFtpFct;
    FHighLevelResult    : Integer;
    FHighLevelFlag      : Boolean;
    FRestartFlag        : Boolean;
    FMsg_WM_FTP_REQUEST_DONE : UINT;
    FMsg_WM_FTP_SENDDATA     : UINT;
    FMsg_WM_FTP_CLOSEDOWN    : UINT;
    FOptions            : TFtpOptions;
    FOnDisplay          : TFtpDisplay;
    FOnDisplayFile      : TFtpDisplay;
    FOnError            : TFtpDisplay;
    FOnCommand          : TFtpCommand;
    FOnResponse         : TNotifyEvent;
    FOnSessionConnected : TSessionConnected;
    FOnSessionClosed    : TSessionClosed;
    FOnStateChange      : TNotifyEvent;
    FOnRequestDone      : TFtpRequestDone;
    FOnReadyToTransmit  : TFtpReadyToTransmit;
    FLocalStream        : TMemoryStream;
    FRequestType        : TFtpRequest;
    FRequestDoneFlag    : Boolean;
    FReceiveBuffer      : array [0..FTP_RCV_BUF_SIZE - 1] of AnsiChar;
    FReceiveLen         : Integer;
    FLastResponse       : String;
    FLastResponseSave   : String;
    FStatusCodeSave     : LongInt;
    FErrorMessage       : String;
    FError              : Word;
    FGetCommand         : String;
    FConnected          : Boolean;
    FSendBuffer         : array [0..FTP_SND_BUF_SIZE - 1] of AnsiChar;
    FOnProgress64       : TFtpProgress64;
    FByteCount          : TFtpBigInt;
    FSizeResult         : TFtpBigInt;
    FNext               : TFtpNextProc;
    FWhenConnected      : TFtpNextProc;
    FDoneAsync          : TFtpNextProc;
    FOkResponses        : array [0..15] of Integer;
    FNextRequest        : TFtpNextProc;
    FServerSaidDone     : Boolean;
    FFileReceived       : Boolean;
    FFileSent           : Boolean;
    FEofFlag            : Boolean;
    FStorAnswerRcvd     : Boolean;
    FPutSessionOpened   : Boolean;
    FDataSocketSentFlag : Boolean;
    FLastMultiResponse  : String;
    FCloseEndTick       : LongWord;
    FCloseEndSecs       : LongWord;
    FKeepAliveSecs      : integer;
    FClientIdStr        : String;
    FPosStart           : TFtpBigInt;
    FPosEnd             : TFtpBigInt;
    FDurationMsecs      : Integer;
    FSocksPassword      : String;
    FSocksPort          : String;
    FSocksServer        : String;
    FSocksUserCode      : String;

    procedure SetKeepAliveSecs (secs: integer);
    procedure   AbortComponent; override;
    procedure   SetMultiThreaded(const Value : Boolean); override;
    procedure   SetOnBgException(const Value: TIcsBgExceptionEvent); override;
    procedure   SetTerminated(const Value: Boolean); override;
    procedure   SetOnMessagePump(const Value: TNotifyEvent); override;
    procedure   SetErrorMessage;
    procedure   LocalStreamWrite(const Buffer; Count : Integer); virtual;
    procedure   LocalStreamWriteString(Str: PAnsiChar; Count: Integer);  overload;
    procedure   LocalStreamWriteString(Str: PWideChar; Count: Integer; ACodePage: LongWord); overload;
    procedure   LocalStreamWriteString(Str: PWideChar; Count: Integer); overload;

    procedure   DataSocketGetDataAvailable(Sender: TObject; ErrCode : word);     //retr
    procedure   DataSocketGetSessionConnected(Sender: TObject; ErrCode : word);  //retr
    procedure   DataSocketGetSessionAvailable(Sender: TObject; ErrCode : word);  //retr
    procedure   DataSocketGetSessionClosed(Sender: TObject; ErrCode : word);     //retr

    procedure   DataSocketPutSessionConnected(Sender: TObject; ErrCode : word);  // stor
    procedure   DataSocketPutDataAvailable(Sender: TObject; ErrCode : word);     // stor
    procedure   DataSocketPutDataSent(Sender: TObject; ErrCode : word);          // stor
    procedure   DataSocketPutSessionAvailable(Sender: TObject; ErrCode : word);  // stor
    procedure   DataSocketPutSessionClosed(Sender: TObject; ErrCode : word);     // stor

    procedure   SendCommand(Cmd : String); virtual;
    procedure   TriggerDisplay(Msg : String); virtual;
    procedure   TriggerReadyToTransmit(var bCancel : Boolean); virtual;
    procedure   TriggerDisplayFile(Msg : String); virtual;
    procedure   TriggerError(Msg: String); virtual;
    procedure   TriggerResponse; virtual;
    procedure   DisplayLastResponse;
    procedure   Notification(AComponent: TComponent; Operation: TOperation); override;
    function    Progress : Boolean; virtual;
    procedure   ControlSocketDnsLookupDone(Sender: TObject; ErrCode: Word);
    procedure   ControlSocketSessionConnected(Sender: TObject; ErrCode: Word); virtual;
    procedure   ControlSocketDataAvailable(Sender: TObject; ErrCode: Word);
    procedure   ControlSocketSessionClosed(Sender: TObject; ErrCode: Word);
    procedure   DataSocketPutAppendInit(const TargetPort, TargetIP : String); virtual;
    procedure   DataSocketGetInit(const TargetPort, TargetIP : String); virtual;
    procedure   TriggerRequestDone(ErrCode: Word);
    procedure   TriggerStateChange;
    procedure   StateChange(NewState : TFtpState);
    procedure   PortAsync; virtual;
    procedure   DoneQuitAsync;
    procedure   ExecAsync(RqType: TFtpRequest; Cmd: String; OkResponses : array of Word; DoneAsync   : TFtpNextProc);
    procedure   NextExecAsync;
    procedure   DoGetAsync(RqType : TFtpRequest);
    procedure   Next1GetAsync;
    procedure   Next2GetAsync;
    procedure   Next3GetAsync;
    procedure   Next1PutAsync;
    procedure   Next2PutAsync;
    procedure   Next3PutAsync;
    procedure   DoPutAppendAsync;
    procedure   DoHighLevelAsync;
    procedure   HighLevelAsync(RqType : TFtpRequest; Fcts : TFtpFctSet);
    procedure   HandleError(const Msg : String);
    function    CheckReady : Boolean;
    procedure   TransfertStats; virtual;
    procedure   SetBinary(Value: Boolean);
    function    GetBinary: Boolean;
    function    GetConnected: Boolean;
    procedure   AllocateMsgHandlers; override;
    procedure   FreeMsgHandlers; override;
    function    MsgHandlersCount: Integer; override;
    procedure   WndProc(var MsgRec: TMessage); override;
    procedure   WMFtpRequestDone(var msg: TMessage); virtual;
    procedure   WMFtpSendData(var msg: TMessage); virtual;
    procedure   WMFtpCloseDown(var msg: TMessage); virtual;
    procedure   DestroyLocalStream;
    procedure   SetLocalStream (Stream:TmemoryStream);
    procedure   SetDataPortRangeStart (NewValue: LongWord);
    procedure   SetDataPortRangeEnd (NewValue: LongWord);
    function    OpenMemoryStream (Buffersize: integer): TmemoryStream;
      {$IFDEF USE_INILE} inline; {$ENDIF}
    procedure   CreateLocalFileStream;
    function    CreateSocket: TWSocket; virtual;
    property    SocketFamily: TSocketFamily read FSocketFamily write FSocketFamily;
    procedure   HandleHttpTunnelError(Sender: TObject; ErrCode: Word;
        TunnelServerAuthTypes: THttpTunnelServerAuthTypes; const Msg: String);
    procedure   HandleSocksError(Sender: TObject; ErrCode: Integer; Msg: String);
    procedure   SetDSocketSndBufSize(const Value: Integer);
    procedure   SetDSocketRcvBufSize(const Value: Integer);
  public
    constructor Create(AOwner: TComponent); override;
    destructor  Destroy; override;

    procedure   OpenAsync;       virtual;
    procedure   ConnectAsync;    virtual;
    procedure   QuitAsync;       virtual;
    procedure   AbortAsync;      virtual;
    procedure   GetAsync;        virtual;
    procedure   ExecGetAsync;    virtual;
    procedure   ReceiveAsync;    virtual;
    procedure   PutAsync;        virtual;
    procedure   ExecPutAsync;    virtual;
    procedure   TransmitAsync;   virtual;

    property    LastResponse      : String               read  FLastResponse;
    property    LastMultiResponse : String               read  FLastMultiResponse;
    property    ErrorMessage      : String               read  FErrorMessage;
    property    DnsResult         : String               read  FDnsResult;
    property    ControlSocket     : TWSocket             read  FControlSocket;
    property    DataSocket        : TWSocket             read  FDataSocket;
    property    Connected         : Boolean              read  GetConnected;
    property    StatusCode        : LongInt              read  FStatusCode;
    property    State             : TFtpState            read  FState;
    property    RequestType       : TFtpRequest          read  FRequestType;
    property    KeepAliveSecs     : Integer              read  FKeepAliveSecs write SetKeepAliveSecs;
    property    LocalStream       : TMemoryStream        read  FLocalStream write SetLocalStream;
    property    OnProgress64      : TFtpProgress64       read  FOnProgress64 write FOnProgress64;
    property    ByteCount         : TFtpBigInt           read  FByteCount;
    property    SizeResult        : TFtpBigInt           read  FSizeResult;
    property    ClientIdStr       : String               read  FClientIdStr write FClientIdStr;
    property    PosStart          : TFtpBigInt           read  FPosStart write FPosStart;
    property    PosEnd            : TFtpBigInt           read  FPosEnd write FPosEnd;
    property    DurationMsecs     : Integer              read  FDurationMsecs;
    property    StartTick         : Integer              read  FStartTime;

    property    StreamSize        : LongInt              read  FStreamSize write FStreamSize;
    property    MemoryPtr         : Pointer              read  FMemoryPtr write FMemoryPtr;
    property    MemoryName        : string               read  FMemoryName write FMemoryName;

    property HostName             : String               read  FHostName write FHostName;
    property Port                 : String               read  FPort write FPort;
    property DataPortRangeStart   : LongWord             read  FDataPortRangeStart write SetDataPortRangeStart;
    property DataPortRangeEnd     : LongWord             read  FDataPortRangeEnd write SetDataPortRangeEnd;
    property ExternalIPv4         : String               read  FExternalIPv4 write FExternalIPv4;
    property LocalAddr            : String               read  FLocalAddr write FLocalAddr;
    property LocalAddr6           : String               read  FLocalAddr6 write FLocalAddr6;
    property DisplayFileFlag      : Boolean              read  FDisplayFileFlag write FDisplayFileFlag;
    property SocksPassword        : String               read  FSocksPassword write FSocksPassword;
    property SocksPort            : String               read  FSocksPort write FSocksPort;
    property SocksServer          : String               read  FSocksServer write FSocksServer;
    property SocksUserCode        : String               read  FSocksUserCode write FSocksUserCode;
    property CloseEndSecs         : LongWord             read  FCloseEndSecs write FCloseEndSecs;
    property DataSocketSndBufSize : Integer              read  FDSocketSndBufSize write SetDSocketSndBufSize default 8192;
    property DataSocketRcvBufSize : Integer              read  FDSocketRcvBufSize write SetDSocketRcvBufSize default 8192;
    property OnDisplay            : TFtpDisplay          read  FOnDisplay write FOnDisplay;
    property OnDisplayFile        : TFtpDisplay          read  FOnDisplayFile write FOnDisplayFile;
    property OnError              : TFTPDisplay          read  FOnError write FOnError;
    property OnCommand            : TFtpCommand          read  FOnCommand write FOnCommand;
    property OnResponse           : TNotifyEvent         read  FOnResponse write FOnResponse;
    property OnSessionConnected   : TSessionConnected    read  FOnSessionConnected write FOnSessionConnected;
    property OnSessionClosed      : TSessionClosed       read  FOnSessionClosed write FOnSessionClosed;
    property OnRequestDone        : TFtpRequestDone      read  FOnRequestDone write FOnRequestDone;
    property OnStateChange        : TNotifyEvent         read  FOnStateChange write FOnStateChange;
    property OnReadyToTransmit    : TFtpReadyToTransmit  read  FOnReadyToTransmit write FOnReadyToTransmit;
    property OnBgException;
  end;

  TMtpClient = class(TCustomMtpCli)
  protected
    FTimeout       : Integer;
    FTimeStop      : LongInt;
    function    Progress : Boolean; override;
    function    Synchronize(Proc : TFtpNextProc) : Boolean; virtual;
    function    WaitUntilReady : Boolean; virtual;
  public
    property    MemoryPtr ;
    constructor Create(AOwner: TComponent); override;
    function    Open       : Boolean;
    function    Connect    : Boolean;
    function    Get        : Boolean;
    function    Put        : Boolean;
    function    MtpPort    : Boolean;
    function    Quit       : Boolean;
    function    Abort      : Boolean;
    function    Receive    : Boolean;
    function    Transmit   : Boolean;
  published
    property    MemoryName ;
    property    StreamSize ;
    property Timeout       : Integer read FTimeout       write FTimeout;
    property MultiThreaded;
    property HostName;
    property Port;
    property DataPortRangeStart;
    property DataPortRangeEnd;
    property ExternalIPv4;
    property LocalAddr;
    property LocalAddr6;
    property DisplayFileFlag;
    property ErrorMessage;
    property SocksPassword;
    property SocksPort;
    property SocksServer;
    property SocksUserCode;
    property DataSocketSndBufSize;
    property OnDisplay;
    property OnDisplayFile;
    property OnCommand;
    property OnError;
    property OnResponse;
    property OnProgress64;
    property OnSessionConnected;
    property OnSessionClosed;
    property OnRequestDone;
    property OnStateChange;
    property OnReadyToTransmit;
    property OnBgException;
    property SocketFamily;
  end;

{$B-}                                 { Enable partial boolean evaluation   }
{$T-}                                 { Untyped pointers                    }
{$X+}                                 { Enable extended syntax              }
{$H+}                                 { Use long strings                    }
{$J+}                                 { Allow typed constant to be modified }


function LookupFTPReq (const RqType: TFtpRequest): String;
function LookupFtpState (const FtpState: TFtpState): String;

procedure register;
implementation
procedure register;
begin
RegisterComponents('ira Mtp', [TMtpClient]);
end;

{$B-}  { Do not evaluate boolean expressions more than necessary }


function LookupFTPReq (const RqType: TFtpRequest): String;
begin
   case RqType of
      ftpNone: result:='none';
      ftpOpenAsync: result:='OpenAsync';
      ftpConnectAsync: result:='ConnectAsync';
      ftpReceiveAsync: result:='ReceiveAsync';
      ftpPortAsync: result:='PortAsync';
      ftpGetAsync: result:='GetAsync';
      ftpQuitAsync: result:='QuitAsync';
      ftpPutAsync: result:='PutAsync';
      ftpRqAbort: result:='RqAbort';
      ftpTransmitAsync: result:='TransmitAsync';
   else
      result:='unknown';
   end;
end;


function LookupFtpState (const FtpState: TFtpState): String;
begin
   case FtpState of
      ftpNotConnected: result := 'Not Connected';
      ftpReady: result := 'Ready';
      ftpInternalReady: result := 'Internal Ready';
      ftpDnsLookup: result := 'DNS Lookup';
      ftpConnected: result := 'Connected';
      ftpAbort: result := 'Abort';
      ftpInternalAbort: result := 'Internal Abort';
      ftpWaitingResponse: result := 'Waiting Response';
   else
      result:='unknown';
   end;
end ;



function GetInteger(Data : PChar; var Number : LongInt) : PChar;
var
    bSign : Boolean;
begin
    Number := 0;
    Result := StpBlk(Data);

    if Result = nil then
        Exit;

    if (Result^ = '-') or (Result^ = '+') then begin
        bSign := (Result^ = '-');
        Inc(Result);
    end
    else
        bSign  := FALSE;

    while (Result^ <> #0) and IsDigit(Result^) do begin
        Number := Number * 10 + ord(Result^) - ord('0');
        Inc(Result);
    end;

    if bSign then
        Number := -Number;
end;



function GetInt64(Data : PChar; var Number : Int64) : PChar;
var
    bSign : Boolean;
begin
    Number := 0;
    Result := StpBlk(Data);

    if Result = nil then
        Exit;

    if (Result^ = '-') or (Result^ = '+') then begin
        bSign := (Result^ = '-');
        Inc(Result);
    end
    else
        bSign  := FALSE;

    while (Result^ <> #0) and IsDigit(Result^) do begin
        Number := Number * 10 + ord(Result^) - ord('0');
        Inc(Result);
    end;

    if bSign then
        Number := -Number;
end;



function GetQuotedString(Data : PChar; var Dst : String) : PChar;
begin
    Dst := '';
    Result := StpBlk(Data);

    if (Result = nil) then
        Exit;

    if Result^ <> '"' then
        Exit;
    Inc(Result);

    while Result^ <> #0 do begin
        if Result^ <> '"' then
            Dst := Dst + Result^
        else begin
            Inc(Result);
            if Result^ <> '"' then
                Break;
            Dst := Dst + Result^;
        end;
        Inc(Result);
    end;
end;


function GetNextString(Data : PChar; var Dst : String) : PChar;
begin
    Dst := '';
    Result := StpBlk(Data);

    if Result = nil then
        Exit;

    while (Result^ <> #0) and (Result^ = #32) do
        Inc(Result);  { skip leading spaces }

    while (Result^ <> #0) and (Result^ <> #32) do begin
        Dst := Dst + Result^;
        Inc(Result);
    end;
end;




{* *                                                                     * *}
{* *                            TCustomMtpCli                            * *}
{* *                                                                     * *}

constructor TCustomMtpCli.Create(AOwner: TComponent);
{$IFDEF MSWINDOWS}
var
    Len : Cardinal;
{$ENDIF}
begin
    inherited Create(AOwner);
    AllocateHWnd;
    FOnDisplay          := nil;
    FOnDisplayFile      := nil;
    FPort               := 'ftp';
    FDataPortRangeStart := 0;
    FDataPortRangeEnd   := 0;
    FCloseEndSecs       := 5;
    FProxyPort          := 'ftp';
    FState              := ftpReady;
    FProxyServer        := '';
    FSocksServer        := '';
    FLocalAddr          := ICS_ANY_HOST_V4;
    FLocalAddr6         := ICS_ANY_HOST_V6;
    FKeepAliveSecs      := 0;
    FSocketFamily       := DefaultSocketFamily;
    FControlSocket      := CreateSocket;
    FControlSocket.ExceptAbortProc    := AbortComponent;
    FControlSocket.OnSessionConnected := ControlSocketSessionConnected;
    FControlSocket.OnDataAvailable    := ControlSocketDataAvailable;
    FControlSocket.OnSessionClosed    := ControlSocketSessionClosed;
    FControlSocket.OnDnsLookupDone    := ControlSocketDnsLookupDone;
    FDataSocket         := CreateSocket;
    FDataSocket.ExceptAbortProc       := AbortComponent;

    FDSocketSndBufSize := 8192;
    FDSocketRcvBufSize := 8192;
end;



destructor TCustomMtpCli.Destroy;
begin
    DestroyLocalStream;
    FDataSocket.Free;
    FControlSocket.Free;
    inherited Destroy;
end;



function TCustomMtpCli.MsgHandlersCount : Integer;
begin
    Result := 3 + inherited MsgHandlersCount;
end;



procedure TCustomMtpCli.AllocateMsgHandlers;
begin
    inherited AllocateMsgHandlers;
    FMsg_WM_FTP_REQUEST_DONE := FWndHandler.AllocateMsgHandler(Self);
    FMsg_WM_FTP_SENDDATA     := FWndHandler.AllocateMsgHandler(Self);
    FMsg_WM_FTP_CLOSEDOWN    := FWndHandler.AllocateMsgHandler(Self);
end;



procedure TCustomMtpCli.FreeMsgHandlers;
begin
    if Assigned(FWndHandler) then begin
        FWndHandler.UnregisterMessage(FMsg_WM_FTP_REQUEST_DONE);
        FWndHandler.UnregisterMessage(FMsg_WM_FTP_SENDDATA);
        FWndHandler.UnregisterMessage(FMsg_WM_FTP_CLOSEDOWN);
    end;
    inherited FreeMsgHandlers;
end;



procedure TCustomMtpCli.WndProc(var MsgRec: TMessage);
begin
    try
         with MsgRec do begin
             if Msg = FMsg_WM_FTP_REQUEST_DONE then
                 WMFtpRequestDone(MsgRec)
             else if Msg = FMsg_WM_FTP_SENDDATA then
                 WMFtpSendData(MsgRec)
             else if Msg = FMsg_WM_FTP_CLOSEDOWN then
                 WMFtpCloseDown(MsgRec)
             else
                 inherited WndProc(MsgRec);
        end;
    except
        on E: Exception do
            HandleBackGroundException(E);
    end;
end;


{* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *}
procedure TCustomMtpCli.AbortComponent;
begin
    try
        AbortAsync;
    except
    end;
    inherited;
end;



procedure TCustomMtpCli.WMFtpRequestDone(var msg: TMessage);
begin
    if Assigned(FOnRequestDone) then
        FOnRequestDone(Self, FRequestType, Msg.LParam);
end;



procedure TCustomMtpCli.Notification(AComponent: TComponent; Operation: TOperation);
begin
    inherited Notification(AComponent, Operation);
    if Operation = opRemove then begin
        if AComponent = FControlSocket then
            FControlSocket := nil
        else if AComponent = FDataSocket then
            FDataSocket := nil;
    end;
end;



procedure TCustomMtpCli.SetDSocketSndBufSize(const Value: Integer);
begin
    if Value < 1024 then
        FDSocketSndBufSize := 1024
    else
        FDSocketSndBufSize := Value;
end;



procedure TCustomMtpCli.SetDSocketRcvBufSize(const Value: Integer);
begin
    if Value < 1024 then
        FDSocketRcvBufSize := 1024
    else
        FDSocketRcvBufSize := Value;
end;



procedure TCustomMtpCli.SetErrorMessage;
begin
    if FErrorMessage = '' then
        FErrorMessage := FLastResponse;
end;


function TCustomMtpCli.CreateSocket: TWSocket;
begin
  Result := TWSocket.Create(Self);
end;



procedure TCustomMtpCli.DestroyLocalStream;
var
    NewSize: Int64;
begin
    if Assigned(FLocalStream) then begin
        FLocalStream.Free;
        FLocalStream := nil;
    end;
end;


function TCustomMtpCli.OpenMemoryStream (Buffersize: integer): TmemoryStream;
begin
    Result := TmemoryStream.Create ;
    Result.SetSize(BufferSize);
end ;


procedure TCustomMtpCli.CreateLocalFileStream;
begin
    try
            FreeAndNil(FLocalStream);
            FLocalStream := OpenMemoryStream(FStreamSize);//960*540*3);
    except
        on E:Exception do begin
            FLastResponse := 'Unable to open local stream ';
            FStatusCode   := 550;
            SetErrorMessage;
            FRequestResult := FStatusCode;
            TriggerRequestDone(FRequestResult);
            exit;
        end;
    end;
end;


procedure TCustomMtpCli.LocalStreamWriteString(Str: PWideChar; Count: Integer;
    ACodePage: LongWord);
begin
    StreamWriteString(FLocalStream, Str, Count, ACodePage);
end;



procedure TCustomMtpCli.LocalStreamWriteString(Str: PWideChar; Count: Integer);
begin
    StreamWriteString(FLocalStream, Str, Count, CP_ACP);
end;



procedure TCustomMtpCli.LocalStreamWriteString(Str: PAnsiChar; Count : Integer);
begin
    FLocalStream.WriteBuffer(Str^, Count);
end;



procedure TCustomMtpCli.LocalStreamWrite(const Buffer; Count : Integer);
begin
    FLocalStream.WriteBuffer(Buffer, Count);
end;



procedure TCustomMtpCli.SetKeepAliveSecs (secs: integer);
begin
    if FKeepAliveSecs <> secs then begin
        if secs = 0 then
            FControlSocket.KeepAliveOnOff := wsKeepAliveOnSystem
        else begin
            FControlSocket.KeepAliveOnOff := wsKeepAliveOnCustom ;
            FControlSocket.KeepAliveTime := LongWord (secs) * 1000;
            if secs < 10 then
                FControlSocket.KeepAliveInterval := 1000
            else
                FControlSocket.KeepAliveInterval := LongWord (secs div 5) * 1000;
        end ;
    end;
    FKeepAliveSecs := secs;
end;




procedure TCustomMtpCli.SetLocalStream(Stream: TmemoryStream);
begin
    FLocalStream := Stream;
end;



procedure TCustomMtpCli.SetDataPortRangeStart(NewValue: LongWord);
begin
    if NewValue > 65535 then
        HandleError('DataPortRangeStart must be in the range 0..65535')
    else
        FDataPortRangeStart := NewValue;
end;



procedure TCustomMtpCli.SetDataPortRangeEnd(NewValue: LongWord);
begin
    if NewValue > 65535 then
        HandleError('DataPortRangeEnd must be in the range 0..65535')
    else
        FDataPortRangeEnd := NewValue
end;



procedure TCustomMtpCli.TriggerDisplay(Msg : String);
begin
    if Assigned(FOnDisplay) then
        FOnDisplay(Self, Msg);
end;



procedure TCustomMtpCli.TriggerDisplayFile(Msg : String);
begin
    if Assigned(FOnDisplayFile) then
        FOnDisplayFile(Self, Msg);
end;



procedure TCustomMtpCli.TriggerError(Msg : String);
begin
    if Assigned(FOnError) then
        FOnError(Self, Msg);
end;



procedure TCustomMtpCli.DisplayLastResponse;
begin
    if Pos('Will attempt to restart', FLastResponse) > 0 then
        TriggerDisplay('< DEBUG !');

    TriggerDisplay('< ' + FLastResponse);
end;



procedure TCustomMtpCli.SetMultiThreaded(const Value : Boolean);
begin
    if Assigned(FDataSocket) then
        FDataSocket.MultiThreaded := Value;
    if Assigned(FControlSocket) then
        FControlSocket.MultiThreaded := Value;
    inherited SetMultiThreaded(Value);
end;



procedure TCustomMtpCli.SetTerminated(const Value: Boolean);
begin
    if Assigned(FDataSocket) then
        FDataSocket.Terminated := Value;
    if Assigned(FControlSocket) then
        FControlSocket.Terminated := Value;
    inherited SetTerminated(Value);
end;



procedure TCustomMtpCli.SetOnBgException(const Value: TIcsBgExceptionEvent);
begin
    if Assigned(FDataSocket) then
        FDataSocket.OnBgException := Value;
    if Assigned(FControlSocket) then
        FControlSocket.OnBgException := Value;
    inherited SetOnBgException(Value);
end;



procedure TCustomMtpCli.SetOnMessagePump(const Value: TNotifyEvent);
begin
    if Assigned(FDataSocket) then
        FDataSocket.OnMessagePump := Value;
    if Assigned(FControlSocket) then
        FControlSocket.OnMessagePump := Value;
    inherited SetOnMessagePump(Value);
end;



procedure TCustomMtpCli.StateChange(NewState : TFtpState);
begin
    if FState <> NewState then begin
        FState := NewState;
        TriggerStateChange;
    end;
end;



function TCustomMtpCli.GetBinary : Boolean;
begin
     Result := (FType = 'I');
end;



procedure TCustomMtpCli.SetBinary(Value : Boolean);
begin
     if Value then
         FType := 'I'
     else
         FType := 'A';
end;



function TCustomMtpCli.Progress : Boolean;
var
    Abort : Boolean;
begin
    Abort := FALSE;
    if Assigned(FOnProgress64) then
        FOnProgress64(Self, FByteCount , Abort);
    if Abort then begin
     //   TriggerDisplay('! Abort requested');
     //   FDataSocket.Close;
        AbortAsync ;
    end;

    Result := not Abort;
end;



procedure TCustomMtpCli.SendCommand(Cmd : String);
var
    RawCmd: AnsiString;
begin
    if Assigned(FOnCommand) then
        FOnCommand(Self, Cmd);
    TriggerDisplay('> ' + Cmd);
    RawCmd := Cmd;
    if FControlSocket.State = wsConnected then
        FControlSocket.SendStr(RawCmd + #13#10)

    else begin
        if cmd = 'QUIT' then
            FStatusCode := 200
        else
            FStatusCode := 550;

         FNextRequest   := nil;
         FDoneAsync     := nil;
         FConnected     := FALSE;
         FRequestResult := FStatusCode;
         FLastResponse  := IntToStr(FStatusCode) + ' not connected';
         if FStatusCode = 550 then begin
            SetErrorMessage;
            TriggerRequestDone(550);
         end
         else
            TriggerRequestDone(0);
    end;
end;



procedure TCustomMtpCli.HandleError(const Msg : String);
begin
    FFctSet           := [];
    FFctPrv           := ftpFctNone;
    FLastResponse     := '';
    FErrorMessage     := '';
    FNextRequest      := nil;
    if Assigned(FOnError) then
        TriggerError(Msg)
    else
        raise FtpException.Create(Msg);
end;



function TCustomMtpCli.CheckReady : Boolean;
begin
    Result := (FState in [ftpReady, ftpInternalReady, ftpConnected]);
    if not Result then
        HandleError('FTP component not ready, state ' + LookupFtpState (FState));
end;



procedure TCustomMtpCli.OpenAsync;
begin
    if not CheckReady then begin
        TriggerDisplay('Not ready for Open');
        Exit;
    end;
    if FConnected then begin
        HandleError('FTP component already connected');
        Exit;
    end;

    if not FHighLevelFlag then
        FRequestType := ftpOpenAsync;

    FRequestDoneFlag     := FALSE;
    FReceiveLen          := 0;
    FRequestResult       := 0;
    FDnsResult           := '';
    FControlSocket.SocketFamily := FSocketFamily;
    FLastResponse        := '';
    FErrorMessage        := '';
    FStatusCode          := 0;

    FControlSocket.SocksAuthentication := socksNoAuthentication;

    FControlSocket.HttpTunnelServer := '';
    FDataSocket.HttpTunnelServer    := '';

    StateChange(ftpDnsLookup);
    FControlSocket.Addr := FHostName;
    FControlSocket.DnsLookup(FHostName);
end;



procedure TCustomMtpCli.ExecAsync(
    RqType      : TFtpRequest;
    Cmd         : String;
    OkResponses : array of Word;
    DoneAsync   : TFtpNextProc);
var
    I : Integer;
begin

    if not((Cmd = 'ABOR') or (Cmd = 'STAT') or (Cmd = 'QUIT')) then begin
        if not CheckReady then begin
            TriggerDisplay('Not ready for next command, Req=' + LookupFTPReq (RqType) + ' - '  + Cmd);
            Exit;
        end;
        if not FConnected then begin
            HandleError('MTP component not connected');
            Exit;
        end;
    end;

    if not FHighLevelFlag then
        FRequestType := RqType;

    for I := 0 to High(OkResponses) do
        FOkResponses[I] := OkResponses[I];
    FOkResponses[High(OkResponses) + 1] := 0;

    FLastMultiResponse := '';
    FRequestDoneFlag   := FALSE;
    FNext              := NextExecAsync;
    FDoneAsync         := DoneAsync;
    FErrormessage      := '';
    StateChange(ftpWaitingResponse);
    SendCommand(Cmd);
end;



procedure TCustomMtpCli.NextExecAsync;
var
    I : Integer;
    p : PChar;
begin
    DisplayLastResponse;

    if not IsDigit(FLastResponse[1]) then
        Exit;
    p := GetInteger(@FLastResponse[1], FStatusCode);
    if p^ = '-' then
        Exit;

    if FOkResponses[0] = 0 then begin

        if FStatusCode >= 500 then begin
            { Not a good response }
            FRequestResult := FStatusCode;
            SetErrorMessage;
        end
        else
            FRequestResult := 0;
    end
    else begin

        for I := 0 to High(FOkResponses) do begin
            if FOkResponses[I] = 0 then begin
                FRequestResult := FStatusCode;
                SetErrorMessage;
                break;
            end;
            if FOkResponses[I] = FStatusCode then begin
                FRequestResult := 0;
                Break;
            end;
        end;
    end;


    if Assigned(FDoneAsync) then
        FDoneAsync
    else
        TriggerRequestDone(FRequestResult);
end;



procedure TCustomMtpCli.QuitAsync;
begin
    DestroyLocalStream;
    FFctPrv := ftpFctQuit;
    ExecAsync(ftpQuitAsync, 'QUIT', [221], DoneQuitAsync);
end;



procedure TCustomMtpCli.DoneQuitAsync;
begin
   StateChange(ftpInternalReady);
   FControlSocket.Close;
end;




procedure TCustomMtpCli.AbortAsync;
begin
    StateChange(ftpAbort);

    FLocalStream.Position :=0;


    //FControlSocket.Abort; // il datasocket viene ricreato con PORT ma il controlsocket no. non c'è QUIT, rimane connesso
    FDataSocket.Abort;
    //FConnected := FALSE;
    StateChange(ftpReady);
end;



procedure TCustomMtpCli.DoHighLevelAsync;
begin
    if FState = ftpAbort then begin
        FFctSet := [];
        FHighLevelResult := 426;
        FErrorMessage    := '426 Operation aborted.';
    end;

    FNextRequest := DoHighLevelAsync;

    if FRequestResult <> 0 then begin
        { Previous command had errors }
        FHighLevelResult := FRequestResult;
        if (FFctPrv = ftpFctQuit) or (not (ftpFctQuit in FFctSet)) then
            FFctSet := []
        else
            FFctSet := [ftpFctQuit];
    end;


    if ftpFctOpen in FFctSet then begin
        FFctPrv := ftpFctOpen;
        FFctSet := FFctSet - [FFctPrv];
        OpenAsync;
        Exit;
    end;




    if ftpFctPort in FFctSet then begin
        FFctPrv := ftpFctPort;
        FFctSet := FFctSet - [FFctPrv];
        PortAsync;
        Exit;
    end;


    if ftpFctGet in FFctSet then begin

        FFctPrv   := ftpFctGet;
        FFctSet   := FFctSet - [FFctPrv];
        ExecGetAsync;
        Exit;
    end;

    if ftpFctPut in FFctSet then begin
        FFctPrv := ftpFctPut;
        FFctSet := FFctSet - [FFctPrv];
        ExecPutAsync;
        Exit;
    end;



    if ftpFctQuit in FFctSet then begin
        FFctPrv := ftpFctQuit;
        FFctSet := FFctSet - [FFctPrv];
        FLastResponseSave := FLastResponse;
        FStatusCodeSave   := FStatusCode;
        QuitAsync;
        Exit;
    end;


    FFctSet          := [];
    FNextRequest     := nil;
    FRequestDoneFlag := FALSE;
    TriggerRequestDone(FHighLevelResult);
end;



procedure TCustomMtpCli.HighLevelAsync(RqType : TFtpRequest; Fcts : TFtpFctSet);
begin
    if FConnected and (ftpFctOpen in Fcts) then begin
        HandleError('MTP component already connected');
        Exit;
    end;
    if not CheckReady then begin
        TriggerDisplay('Not ready for Request, Req=' + LookupFTPReq (RqType));
        Exit;
    end;
    FLastResponseSave := FLastResponse;
    FStatusCodeSave   := -1;
    FRequestType      := RqType;
    FRequestResult    := 0;
    FFctSet           := Fcts;
    FFctPrv           := ftpFctNone;
    FHighLevelResult  := 0;
    FHighLevelFlag    := TRUE;
    FLastResponse     := '';
    FErrorMessage     := '';
    FRestartFlag      := FALSE;
    FNextRequest      := nil;
    DoHighLevelAsync;
end;



procedure TCustomMtpCli.ConnectAsync;
begin
    HighLevelAsync(ftpConnectAsync,
                   [ftpFctOpen]);
end;



procedure TCustomMtpCli.ReceiveAsync;
begin
    HighLevelAsync(ftpReceiveAsync,
                   [ftpFctOpen, ftpFctPort, ftpFctGet,  ftpFctQuit]);
end;



procedure TCustomMtpCli.PutAsync;
begin
	DataSocket.LastError := 0;
HighLevelAsync(ftpPutAsync, //
                 [ftpFctPort, ftpFctPut]);
    if DataSocket.LastError <> 0 then
       raise FtpException.Create('Socket Error - ' +
                              GetWinsockErr(DataSocket.LastError));
end;




procedure TCustomMtpCli.TransmitAsync;
begin
    HighLevelAsync(ftpTransmitAsync,
                   [ftpFctOpen,  ftpFctPort,  ftpFctPut,  ftpFctQuit]);
end;



procedure TCustomMtpCli.GetAsync;
begin
    HighLevelAsync(ftpGetAsync, [ftpFctPort, ftpFctGet]);
end;




procedure TCustomMtpCli.DataSocketGetDataAvailable( Sender  : TObject; ErrCode : word);
var
    Len     : Integer;
    Buffer  : array [1..FTP_RCV_BUF_SIZE] of AnsiChar;
    aSocket : TWSocket;
    I, J    : Integer;
    Line    : AnsiString;
    ACodePage : LongWord;
begin
    if not Progress then
        Exit;

    aSocket := Sender as TWSocket;

    Len := aSocket.Receive(@Buffer[1], High(Buffer));
{TriggerDisplay('! Data received ' + IntToStr(Len));}
    if Len = 0 then
    else if Len < 0 then begin
        if (aSocket.State = wsConnected) and
           (aSocket.LastError <> WSAEWOULDBLOCK) then begin
            TriggerDisplay('! Data: Receive Error - ' +
                                     GetWinsockErr(aSocket.LastError));
            aSocket.Shutdown(2);
            Exit;
        end;
    end
    else begin

        if FState in [ftpAbort, ftpInternalAbort] then begin
            TriggerDisplay('! Data ignored while aborting');
            exit;
        end ;
        if FLocalStream <> nil then begin
            try
                LocalStreamWrite(Buffer, Len);
            except
                TriggerDisplay('! Error writing local file');
                aSocket.Shutdown(2);
                Exit;
            end;
        end;

        FByteCount := FByteCount + Len;


        SetLength(Line, Len);
        Move(Buffer[1], Line[1], Length(Line));
        TriggerDisplayFile(AnsiToUnicode(Line, ACodePage));
    end;

end;



procedure TCustomMtpCli.DataSocketGetSessionConnected(Sender  : TObject; ErrCode : word);
begin
    FDataSocket.OnSessionClosed := DataSocketGetSessionClosed;
    FDataSocket.OnDataAvailable := DataSocketGetDataAvailable;
    FDataSocket.OnDataSent      := nil;

    FStartTime := LongInt(IcsGetTickCount);
    FDurationMsecs := 0;

    if ErrCode <> 0 then begin
        FLastResponse := 'Unable to establish data connection - ' +
                         WSocketGetErrorMsgFromErrorCode(ErrCode);
        FStatusCode   := 550;
        SetErrorMessage;
        FDataSocket.Close;
        FRequestResult := FStatusCode;
        TriggerRequestDone(FRequestResult);
    end
    else begin
        if FDataSocket.SocketRcvBufSize <> FDSocketRcvBufSize then
            FDataSocket.SocketRcvBufSize := FDSocketRcvBufSize;
    end;
end;



procedure TCustomMtpCli.DataSocketPutSessionConnected(Sender  : TObject; ErrCode : word);
begin
    FDataSocket.OnSessionClosed := DataSocketPutSessionClosed;
    FDataSocket.OnDataAvailable := nil;
    FDataSocket.OnDataSent      := nil;

    FPutSessionOpened := TRUE;

    FStartTime := LongInt(IcsGetTickCount);
    FDurationMsecs := 0;

    if ErrCode <> 0 then begin
        FLastResponse := 'Unable to establish data connection - ' +
                         WSocketGetErrorMsgFromErrorCode(ErrCode);
        FStatusCode   := 550;
        SetErrorMessage;
        FDataSocket.Close;
        FRequestResult := FStatusCode;
        TriggerRequestDone(FRequestResult);
        Exit;
    end;
    if FDataSocket.SocketSndBufSize <> FDSocketSndBufSize then
        FDataSocket.SocketSndBufSize := FDSocketSndBufSize;
    StateChange(ftpWaitingResponse);
    FNext := Next1PutAsync;

    SendCommand('STOR ' + IntToStr(FStreamSize ) + ' ' + MemoryName );
end;



procedure TCustomMtpCli.DataSocketGetSessionAvailable(Sender  : TObject; ErrCode : word);
var
    aSocket : TSocket;
begin
    aSocket := FDataSocket.Accept;

    FDataSocket.Close;


    FDataSocket.OnSessionClosed  := DataSocketGetSessionClosed;
    FDataSocket.OnDataAvailable  := DataSocketGetDataAvailable;
    FDataSocket.OnDataSent       := nil;
    FDataSocket.HSocket          := aSocket;
    if FDataSocket.SocketRcvBufSize <> FDSocketRcvBufSize then
        FDataSocket.SocketRcvBufSize := FDSocketRcvBufSize;
    FDataSocket.ComponentOptions := [wsoNoReceiveLoop];

    FStartTime := LongInt(IcsGetTickCount);
    FDurationMsecs := 0;
end;



procedure TCustomMtpCli.DataSocketGetSessionClosed(Sender  : TObject; ErrCode : word);
begin
    FLocalStream.Position :=0;
    FFileReceived := TRUE;
    FError        := ErrCode;
    Next3GetAsync;
end;



procedure TCustomMtpCli.DataSocketPutSessionAvailable(Sender  : TObject; ErrCode : word);
var
    aSocket : TSocket;
begin
    aSocket := FDataSocket.Accept;

    FDataSocket.Close;

    FDataSocket.OnSessionClosed  := DataSocketPutSessionClosed;
    FDataSocket.OnDataAvailable  := DataSocketPutDataAvailable;
    FDataSocket.OnDataSent       := DataSocketPutDataSent;
{   FDataSocket.OnDisplay        := FOnDisplay; } { Debugging only }
    FDataSocket.HSocket          := aSocket;
    if FDataSocket.SocketSndBufSize <> FDSocketSndBufSize then
        FDataSocket.SocketSndBufSize := FDSocketSndBufSize;
    FDataSocket.ComponentOptions := [wsoNoReceiveLoop];

    // Chiusura sicura del socket
    FDataSocket.LingerOnOff   := wsLingerOn; //wsLingerOff;// wsLingerOn;
    FDataSocket.LingerTimeout := 10;//10;   0 e off
    FDataSocket.SetLingerOption;
    FPutSessionOpened := TRUE;
    if FStorAnswerRcvd and (FStartTime = 0) then
        PostMessage(Handle, FMsg_WM_FTP_SENDDATA, 0, 0);

end;



procedure TCustomMtpCli.WMFtpSendData(var msg: TMessage);
begin
    FStartTime := LongInt(IcsGetTickCount);
    FDurationMsecs := 0;

    if not FDataSocketSentFlag then
        DataSocketPutDataSent(FDataSocket, 0);
end;



procedure  TCustomMtpCli.WMFtpCloseDown(var msg: TMessage);
begin
    if (FDataSocket.BufferedByteCount = 0) or
       (FCloseEndTick < IcsGetTickCount) then begin
        FDataSocket.ShutDown(1);
        FEofFlag := TRUE;
    end
    else if ((FControlSocket.State = wsConnected) and
             (FDataSocket.State    = wsConnected)) then
        PostMessage(Handle, FMSG_WM_FTP_CLOSEDOWN, 0, 0);
end;



procedure TCustomMtpCli.DataSocketPutDataSent( Sender  : TObject; ErrCode : word);
var
    Count : Integer;
begin
    if (FLocalStream = nil) or (not Progress) then
        Exit;
    if FLocalStream = nil then
        Exit;

    if ErrCode <> 0 then begin
        TriggerDisplay('! Error sending data - ' + GetWinsockErr(ErrCode));
        FDataSocket.Close;
        Exit;
    end;

    if FEofFlag or (not FStorAnswerRcvd) or (not FPutSessionOpened) then begin
        Exit;
    end;

    if not FDataSocketSentFlag then
        FDataSocketSentFlag := TRUE;

    try
            Count := FLocalStream.Read(FSendBuffer, SizeOf(FSendBuffer));
        if Count > 0 then begin
            FByteCount := FByteCount + Count;
            FDataSocket.Send(@FSendBuffer, Count);
        end
        else begin { EOF }
            {$IFNDEF VER80}
            FCloseEndTick := IcsGetTickCount + (FCloseEndSecs * 1000);
            PostMessage(Handle, FMsg_WM_FTP_CLOSEDOWN, 0, 0);
            exit;
            {$ENDIF}
            FDataSocket.ShutDown(1);
            FEofFlag := TRUE;
        end;
    except
        on E:Exception do begin
            TriggerDisplay('! Error reading file ' + E.ClassName + ': ' + E.Message);
            FDataSocket.Close;
        end;
    end;
end;



procedure TCustomMtpCli.DataSocketPutSessionClosed(Sender  : TObject; ErrCode : word);
begin
    FLocalStream.Position :=0;
    FFileSent := TRUE;
    FError    := ErrCode;
    Next3PutAsync;
end;



procedure TCustomMtpCli.DataSocketPutDataAvailable(Sender  : TObject; ErrCode : word);
var
    Buffer  : array [1..2048] of Byte;
    aSocket : TWSocket;
begin
    aSocket := Sender as TWSocket;
    aSocket.Receive(@Buffer[1], High(Buffer));
end;



procedure TCustomMtpCli.TransfertStats;
var
    Buffer   : String;
    BytesSec : Int64 ;
    Duration : Int64 ;
begin
    FStopTime := LongInt(IcsGetTickCount);
    Buffer    := IntToKByte(FByteCount) + 'bytes received/sent in ';
    if LongWord (FStopTime) >= LongWord (FStartTime) then
        Duration := LongWord (FStopTime) - LongWord (FStartTime)
    else
        Duration := ($FFFFFFFF - LongWord (FStartTime)) + LongWord (FStopTime);
    if Duration < 5000 then
        Buffer := Buffer + IntToStr(Duration) + ' milliseconds'
    else begin
        Buffer := Buffer + IntToStr(Duration div 1000) + ' seconds';
    if FStopTime <> FStartTime then begin
        if FByteCount > 32767 then
                BytesSec := 1000 * (FByteCount div Duration)
        else
                BytesSec := (1000 * FByteCount) div Duration;
            Buffer := Buffer + ' (' + IntToKByte(BytesSec) + 'bytes/sec)';
    end;
    end;
    FDurationMsecs := Integer (Duration);
    TriggerDisplay('! ' + Buffer);
end;



procedure TCustomMtpCli.ExecGetAsync;
begin
    DoGetAsync(ftpGetAsync);
end;





procedure TCustomMtpCli.DataSocketGetInit(const TargetPort, TargetIP : String);
begin
    FDataSocket.Port               := TargetPort;
    FDataSocket.Addr               := TargetIP;
    FDataSocket.LocalAddr          := FLocalAddr;
    FDataSocket.LocalAddr6         := FLocalAddr6;
    FDataSocket.OnSessionConnected := DataSocketGetSessionConnected;
    FDataSocket.LingerOnOff        := wsLingerOff;
    FDataSocket.LingerTimeout      := 0;
    FDataSocket.ComponentOptions   := [wsoNoReceiveLoop];

    FDataSocket.SocksAuthentication := socksNoAuthentication;
end;



function GetZlibCacheFileName(const S : String) : String;
var
    I : Integer;
    Ticks: String;
begin
    Result := AnsiLowercase (S);
    if Length(Result) = 0 then Result := 'temp';
    for I := 1 to Length(Result) do begin
        if (Result [I] = '\') or (Result [I] = '.') or
                           (Result [I] = ':') then Result[I] := '_';
    end;
    Ticks := IntToStr(IcsGetTickCountX);
    I := Length(Ticks);
    if I < 6 then Ticks := '123' + Ticks;
    Result := Result + '_' + Copy (Ticks, I-6, 6) + '.zlib';
end;



(* Riceve un file *)
procedure TCustomMtpCli.DoGetAsync(RqType : TFtpRequest);
var
    Temp       : String;
    I {, MaxWbits} : Integer;
    TargetPort : WORD;    { 10/30/99 }
    TargetIP   : String;
    NewPos     : TFtpBigInt;
    Delim      : Char;
    DelimCnt, N: Integer;
begin
    if not FConnected then begin
        HandleError(FGetCommand + ': not connected');
        Exit;
    end;

    if not FHighLevelFlag then
        FRequestType := RqType;

    FGetCommand := 'RETR';


    FServerSaidDone    := FALSE;
    FFileReceived      := FALSE;
    FRequestDoneFlag   := FALSE;
    FStartTime         := 0;
    FByteCount         := 0;
    FDurationMsecs     := 0;
    FError             := 0;

    FDataSocket.OnSessionAvailable := DataSocketGetSessionAvailable;

    { open the destination file }
    { Don't open a file if we're on FDisplayFileFlag }
    if not FDisplayFileFlag then
    try
        DestroyLocalStream;
            if not Assigned(FLocalStream)then begin
                FLocalStream := OpenMemoryStream(FStreamSize);
            end;
    except
        on E:Exception do begin
            FLastResponse := 'Unable to open local stream ' + ': ' + E.Message;
            FStatusCode   := 550;
            SetErrorMessage;
            FDataSocket.Close;
            FRequestResult := FStatusCode;
            TriggerRequestDone(FRequestResult);
            exit;
        end;
    end;


    StateChange(ftpWaitingResponse);
    FNext := Next1GetAsync;
    SendCommand(FGetCommand);
end;



(*Qui arriviamo quando abbiamo ricevuto il response per il comando RETR che abbiamo invito prima *)
procedure TCustomMtpCli.Next1GetAsync;
begin
    DisplayLastResponse;
    GetInteger(@FLastResponse[1], FStatusCode);
    if not (((FStatusCode div 10) = 15) or
            (FStatusCode = 125)) then begin
        SetErrorMessage;
        FNext := nil;
        FDataSocket.Close;
        DestroyLocalStream;

        FRequestResult := FStatusCode;
        TriggerRequestDone(FRequestResult);
        Exit;
    end;
    FNext := Next2GetAsync;
end;



(*Qui arriviamo quando MtpServer ha spedito il file che abbiamo chiesot con GET *)
procedure TCustomMtpCli.Next2GetAsync;
begin
    DisplayLastResponse;
    GetInteger(@FLastResponse[1], FStatusCode);
    if not ((FStatusCode = 125) or (FStatusCode = 226) or
            (FStatusCode = 250)) then begin
        SetErrorMessage;
        DestroyLocalStream;
        FDataSocket.Close;
        TriggerDisplay('! RETR/LIST/NLST Failed');
        FRequestResult := FStatusCode;
        TriggerRequestDone(FRequestResult);
        Exit;
    end;
    FServerSaidDone := TRUE;
    Next3GetAsync;
end;



(*Qui arriviamo quando abbiamo ricevuto il file dal MtpServer o quando abbiamo una risposta *)
procedure TCustomMtpCli.Next3GetAsync;
begin
    if (not FServerSaidDone) or (not FFileReceived) then
        Exit;

    { Display statistics }
    TransfertStats;

    FRequestResult := FError;
    TriggerRequestDone(FRequestResult);
end;


procedure TCustomMtpCli.ExecPutAsync;
begin
    FAppendFlag  := FALSE;
    FRequestType := ftpPutAsync;
    DoPutAppendAsync;
end;


procedure TCustomMtpCli.DataSocketPutAppendInit(const TargetPort, TargetIP : String);
begin
    FDataSocket.Port               := TargetPort;
    FDataSocket.Addr               := TargetIP;
    FDataSocket.LocalAddr          := FLocalAddr;
    FDataSocket.LocalAddr6         := FLocalAddr6;
    FDataSocket.OnSessionConnected := DataSocketPutSessionConnected;
    FDataSocket.LingerOnOff        := wsLingerOff;
    FDataSocket.LingerTimeout      := 0;
    FDataSocket.ComponentOptions   := [wsoNoReceiveLoop];
    FDataSocketSentFlag            := FALSE;
    FDataSocket.SocksAuthentication := socksNoAuthentication;
end;



procedure TCustomMtpCli.DoPutAppendAsync;
var
    Temp        : String;
    I           : Integer;
    TargetPort  : WORD;
    TargetIP    : String;
    bCancel     : Boolean;
    NewPos      : TFtpBigInt;
    Uploadsize  : TFtpBigInt;
    Count : Integer;

begin
    if not FConnected then begin
        HandleError('STOR/APPE: not connected');
        Exit;
    end;

    FServerSaidDone    := FALSE;
    FFileSent          := FALSE;
    FRequestDoneFlag   := FALSE;
    FPutSessionOpened  := FALSE;
    FStorAnswerRcvd    := FALSE;
    FStartTime         := 0;
    FDurationMsecs     := 0;
    FByteCount         := 0;
    FError             := 0;

    bCancel := FALSE;
    TriggerReadyToTransmit(bCancel);
    if bCancel then begin
        FErrorMessage := '426 Transmit cancelled by application';
        FStatusCode   := 426;
        TriggerDisplay('! ' + FErrorMessage);
        FRequestResult := FStatusCode;
        TriggerRequestDone(FRequestResult);
        Exit;
    end;

    FDataSocket.OnSessionAvailable := DataSocketPutSessionAvailable;

    try
        DestroyLocalStream;
        FEofFlag     := FALSE;
        if not Assigned(FLocalStream) then begin
            FLocalStream := OpenMemoryStream(FStreamSize);
        end;
    except
        on E:Exception do begin
            FLastResponse := 'Unable to open local file ' + ': ' + E.Message;
            FStatusCode   := 426;
            SetErrorMessage;
            TriggerDisplay('! ' + FErrorMessage);
            FDataSocket.Close;
            FRequestResult := FStatusCode;
            TriggerRequestDone(FRequestResult);
            Exit;
        end;
    end;

    Uploadsize := FStreamSize - FLocalStream.Position;
    Count := FLocalStream.WriteData  ( MemoryPtr , FStreamSize );
    FLocalStream.Position:=0;
    TriggerDisplay('! Upload Size ' + IntToKByte (Uploadsize)) ;


    StateChange(ftpWaitingResponse);
    FNext := Next1PutAsync;

    SendCommand('STOR ' + IntToStr(fStreamSize) + ' ' + MemoryName );
end;



(*Qui arriviamo quando abbiamo ricevuto la risposta per il comando STOR che abbiamo inviato prima *)
procedure TCustomMtpCli.Next1PutAsync;
var
    p : PChar;
begin
    DisplayLastResponse;
    if not IsDigit(FLastResponse[1]) then
        Exit;
    p := GetInteger(@FLastResponse[1], FStatusCode);
    if p^ = '-' then
        Exit;

    if not ((FStatusCode = 150) or (FStatusCode = 125)) then begin
        SetErrorMessage;
        FNext := nil;
        FDataSocket.Close;
        DestroyLocalStream;

        FRequestResult := FStatusCode;
        TriggerRequestDone(FRequestResult);
        Exit;
    end;

        FStorAnswerRcvd := TRUE;
        if FPutSessionOpened and (FStartTime = 0) then
            PostMessage(Handle, FMsg_WM_FTP_SENDDATA, 0, 0);


    FNext := Next2PutAsync;
end;



(*Qui arriviamo quando MtpServer ha ricevuto il file che abbiamo spedito con STOR *)
procedure TCustomMtpCli.Next2PutAsync;
var
    p : PChar;
begin
    DisplayLastResponse;
    if not IsDigit(FLastResponse[1]) then
        Exit;
    p := GetInteger(@FLastResponse[1], FStatusCode);
    if p^ = '-' then
        Exit;
    if not ((FStatusCode = 226) or (FStatusCode = 250)) then begin
        SetErrorMessage;
        DestroyLocalStream;
        FDataSocket.Close;
        TriggerDisplay('! STOR Failed');
        FRequestResult := FStatusCode;
        TriggerRequestDone(FRequestResult);
        Exit;
    end;
    FServerSaidDone := TRUE;
    Next3PutAsync;
end;



(*Qui arriviamo quando abbiamo trasferito il file o MtpServer ci dice che l'ha ricevuto*)
procedure TCustomMtpCli.Next3PutAsync;
begin
    if (not FServerSaidDone) or (not FFileSent) then
        Exit;

    TransfertStats;

    // Resetta il puntatore dello stream
    FLocalStream.Position :=0;
    FRequestResult := FError;
    TriggerRequestDone(FRequestResult);
end;



procedure TCustomMtpCli.PortAsync;
type
    T4Bytes = array[0..3] of Byte;
    P4Bytes = ^T4Bytes;
var
    Msg          : String;
    saddr        : TSockAddrIn6;
    saddrlen     : Integer;
    DataPort     : LongWord;
    IPAddr       : TInAddr;
    StartDataPort: LongWord;
begin
    if not FConnected then begin
        HandleError('FTP component not connected');
        Exit;
    end;
    FDataSocket.Proto              := 'tcp';
    if FControlSocket.CurrentSocketFamily = sfIPv6 then
        FDataSocket.Addr := ICS_ANY_HOST_V6
    else
        FDataSocket.Addr := ICS_ANY_HOST_V4;
    FDataSocket.Port               := AnsiChar('0');
    FDataSocket.OnSessionAvailable := nil;
    FDataSocket.OnSessionClosed    := nil;
    FDataSocket.OnDataAvailable    := nil;
    FDataSocketSentFlag            := FALSE;

        if (ftpFctGet in FFctSet) then
            FDataSocket.OnSessionAvailable := DataSocketGetSessionAvailable
        else if ftpFctPut in FFctSet then
            FDataSocket.OnSessionAvailable := DataSocketPutSessionAvailable;
        FDataSocket.LingerOnOff        := wsLingerOff;// wsLingerOn;
        FDataSocket.LingerTimeout      := 0;//10

        if (FDataPortRangeStart = 0) and (FDataPortRangeEnd = 0) then begin
            FDataSocket.Listen;
            saddrLen  := SizeOf(saddr);
            FDataSocket.GetSockName(PSockAddrIn(@saddr)^, saddrLen);
            DataPort  := WSocket_ntohs(saddr.sin6_port);
        end
        else begin
            if FDataPortRangeStart > FDataPortRangeEnd then begin
                HandleError('DataPortRangeEnd must be greater than DataPortRangeStart');
                Exit;
            end;
            if (FLastDataPort < FDataPortRangeStart) or
               (FLastDataPort > FDataPortRangeEnd) then
                FLastDataPort := FDataPortRangeStart;
            DataPort      := FLastDataPort;
            StartDataPort := DataPort;
            while TRUE do begin
                FDataSocket.Port := IntToStr(DataPort);
                try
                    FDataSocket.Listen;
                    break;
                except
                    if FDataSocket.LastError = WSAEADDRINUSE then begin
                        DataPort := DataPort + 1;
                        if DataPort > FDataPortRangeEnd then
                            DataPort := FDataPortRangeStart;
                        if DataPort = StartDataPort then begin
                            HandleError('All ports in DataPortRange are in use');
                            Exit;
                        end;
                    end
                    else begin
                        HandleError('Data connection winsock bind failed - ' +
                                    GetWinsockErr(FDataSocket.LastError));
                        Exit;
                    end;
                end;
            end;
            FLastDataPort := DataPort + 1;
            if FLastDataPort > FDataPortRangeEnd then
                FLastDataPort := FDataPortRangeStart;
        end;

    saddrlen := SizeOf(saddr);
    FControlSocket.GetSockName(PSockAddrIn(@saddr)^, saddrlen);
    IPAddr   := PSockAddrIn(@saddr).sin_addr;

        if saddr.sin6_family = AF_INET6 then
        begin
            Msg := 'EPRT |2|' +
                   WSocketIPv6ToStr(PIcsIPv6Address(@saddr.sin6_addr)^) +
                   '|' + IntToStr(DataPort) + '|';
        end
        else
        if WSocketIsIPv4(FExternalIPv4) then
            Msg := Format('PORT %s,%d,%d',
                          [StringReplace(FExternalIPv4, '.', ',', [rfReplaceAll]),
                           IcsHiByte(DataPort),
                           IcsLoByte(DataPort)])
        else
        if FControlSocket.sin.sin_addr.s_addr = WSocket_htonl($7F000001) then
            Msg := Format('PORT 127,0,0,1,%d,%d',
                          [IcsHiByte(DataPort),
                           IcsLoByte(DataPort)])
        else
          {$IFDEF MSWINDOWS}
            Msg := Format('PORT %d,%d,%d,%d,%d,%d',
                          [ord(IPAddr. S_un_b.s_b1),
                           ord(IPAddr.S_un_b.s_b2),
                           ord(IPAddr.S_un_b.s_b3),
                           ord(IPAddr.S_un_b.s_b4),
                           IcsHiByte(DataPort),
                           IcsLoByte(DataPort)]);
          {$ENDIF}
          {$IFDEF POSIX}
            Msg := Format('PORT %d,%d,%d,%d,%d,%d',
                          [P4Bytes(@IPAddr.s_addr)^[0],
                           P4Bytes(@IPAddr.s_addr)^[1],
                           P4Bytes(@IPAddr.s_addr)^[2],
                           P4Bytes(@IPAddr.s_addr)^[3],
                           IcsHiByte(DataPort),
                           IcsLoByte(DataPort)]);
          {$ENDIF}

    FByteCount := 0;
    FFctPrv    := ftpFctPort;
    if saddr.sin6_family = AF_INET6 then
        ExecAsync(ftpPortAsync, Msg, [200, 229], nil)
    else
        ExecAsync(ftpPortAsync, Msg, [200, 227], nil);
end;



procedure TCustomMtpCli.ControlSocketDnsLookupDone(Sender  : TObject; ErrCode : Word);
begin
    if ErrCode <> 0 then begin
        FLastResponse  := '500 DNS lookup error - ' + GetWinsockErr(ErrCode) ;
        FStatusCode    := 500;
        FRequestResult :=  FStatusCode;
        SetErrorMessage;
        TriggerRequestDone(ErrCode);
    end
    else begin
        FDnsResult               := FControlSocket.DnsResult;
        FControlSocket.Addr      := FDnsResult;
        FControlSocket.LocalAddr := FLocalAddr;
        FControlSocket.LocalAddr6 := FLocalAddr6;
        FControlSocket.Proto     := 'tcp';

        FControlSocket.Port  := FPort;
{       FControlSocket.OnDisplay := FOnDisplay; } { Debugging only }


        StateChange(ftpReady);
        try
            FControlSocket.Connect;
        except
            on E:Exception do begin
                FLastResponse := '500 ' + E.ClassName + ': ' + E.Message;
                FStatusCode   := 500;
                FRequestResult :=  FStatusCode;
                SetErrorMessage;
                TriggerRequestDone(FStatusCode);
            end;
        end;
    end;
end;



procedure TCustomMtpCli.HandleHttpTunnelError(
    Sender                : TObject;
    ErrCode               : Word;
    TunnelServerAuthTypes : THttpTunnelServerAuthTypes;
    const Msg             : String);
begin
    FLastResponse := Msg;
end;



procedure TCustomMtpCli.HandleSocksError(
    Sender  : TObject;
    ErrCode : Integer;
    Msg     : String);
begin
    FLastResponse := Msg;
end;



procedure TCustomMtpCli.ControlSocketSessionConnected(Sender: TObject; ErrCode: Word);
begin
    if ErrCode <> 0 then begin
      {$IFDEF POSIX}
        if (ErrCode <= WSAELAST) then
      {$ELSE}
        if (ErrCode >= WSABASEERR) and (ErrCode < ICS_SOCKS_BASEERR) then
      {$ENDIF}
            FLastResponse  := '500 Connect error - ' + GetWinsockErr(ErrCode)
        else if WSocketIsProxyErrorCode(ErrCode) then
            FLastResponse  := '500 Connect error - ' + FLastResponse + ' (#' + IntToStr(ErrCode) + ')'
        else
            FLastResponse  := '500 Connect Unknown Error (#' + IntToStr(ErrCode) + ')';
        FStatusCode    := 500;
        FRequestResult := FStatusCode;
        SetErrorMessage;
        FNextRequest   := nil;
        TriggerRequestDone(ErrCode);
        FControlSocket.Close;
        StateChange(ftpReady);
    end
    else begin
        FConnected := TRUE;

            StateChange(ftpConnected);
            if Assigned(FOnSessionConnected) then
                FOnSessionConnected(Self, ErrCode);

            if Assigned(FWhenConnected) then
                FWhenConnected
            else begin
                TriggerRequestDone(0);
            end;
    end;
end;



procedure TCustomMtpCli.ControlSocketDataAvailable(Sender: TObject; ErrCode: Word);
var
    Len  : Integer;
    I, J : Integer;
    p    : PChar;
    Feat : String;
    ACodePage : LongWord;
    RawResponse: AnsiString;
    x     : integer;
const
    NewLine =  #13#10 ;
begin
    Len := FControlSocket.Receive(@FReceiveBuffer[FReceiveLen],
                                  SizeOf(FReceiveBuffer) - FReceiveLen - 1);

    if FRequestType = ftpRqAbort then
        Exit;

    if Len = 0 then begin
        Exit;
    end;
    if Len < 0 then
        Exit;

    FReceiveBuffer[FReceiveLen + Len] := #0;
    FReceiveLen := FReceiveLen + Len;

    while FReceiveLen > 0 do begin
        if ftpAcceptLF in FOptions then begin
            I := Pos(AnsiChar(10), FReceiveBuffer);
            J := I;
        end
        else begin
            I := Pos(AnsiString(#13#10), FReceiveBuffer);
            J := I + 1;
        end;
        if I <= 0 then
            break;
        if I > FReceiveLen then
            break;
        RawResponse := Copy(FReceiveBuffer, 1, I);

        while (Length(RawResponse) > 0) and
              IsCRLF(RawResponse[Length(RawResponse)]) do
             SetLength(RawResponse, Length(RawResponse) - 1);
        FLastResponse := RawResponse ;

            if LongInt(Length(FLastMultiResponse)) < 65536 then
                FLastMultiResponse := FLastMultiResponse + FLastResponse + #13#10;
        TriggerResponse;

        FReceiveLen := FReceiveLen - J;
        if FReceiveLen > 0 then
            Move(FReceiveBuffer[J], FReceiveBuffer[0], FReceiveLen + 1)
        else if FReceiveLen < 0 then
            FReceiveLen := 0;


         if FState = ftpWaitingResponse then begin
            if (FLastResponse = '') or
               (not IsDigit(FLastResponse[1])) then begin
                DisplayLastResponse;
                Continue;
            end;
            p := GetInteger(@FLastResponse[1], FStatusCode);

                x:= pos ('150 Opening retrieve data connection for ',FLastResponse,1);
                if x <> 0  then begin
                  LocalStream.SetSize(  StrToInt(RightStr(FLastResponse, length(FLastResponse) - 41 )  ));
                  LocalStream.Position :=0;
                end;
            if p^ = '-' then begin

                DisplayLastResponse;
                Continue;
            end;
            if Assigned(FNext) then
                FNext
            else begin
                HandleError('Program error: FNext is nil');
                Exit;
            end;
        end
        else
            DisplayLastResponse;
    end;
end;



procedure TCustomMtpCli.ControlSocketSessionClosed(
    Sender  : TObject;
    ErrCode : Word);
var
    LClosedState : TFtpState;
begin
    if (ErrCode <> 0) and (FState = ftpInternalReady) and
       ((FRequestType = ftpQuitAsync) or (FFctPrv = ftpFctQuit)) then
        ErrCode := 0;

    LClosedState := FState;
    if FConnected then begin
        FConnected := FALSE;
        if FState <> ftpAbort then
            StateChange(ftpNotConnected);
        if Assigned(FOnSessionClosed) then
            FOnSessionClosed(Self, ErrCode);
    end;
    if FState <> ftpAbort then
        StateChange(ftpInternalReady);
    if FRequestType <> ftpRqAbort then begin
        if (ErrCode <> 0) or ((FRequestType <> ftpQuitAsync) and
           (LClosedState in [ ftpWaitingResponse])) then begin
            FLastResponse  := '500 Control connection closed - ' +
                               WSocketGetErrorMsgFromErrorCode(ErrCode);
            FStatusCode    := 500;
            FRequestResult := FStatusCode;
            SetErrorMessage;
        end;
        TriggerRequestDone(FRequestResult);
    end;
end;



procedure TCustomMtpCli.TriggerStateChange;
begin
    if Assigned(FOnStateChange) then
        FOnStateChange(Self);
end;



procedure TCustomMtpCli.TriggerRequestDone(ErrCode: Word);
begin
    if not FRequestDoneFlag then begin
        FRequestDoneFlag := TRUE;
        if (ErrCode = 0) and Assigned(FNextRequest) then begin
            if (FState <> ftpAbort) then  StateChange(ftpInternalReady);
            FNextRequest;
        end
        else begin
            StateChange(ftpReady);
            if FDataSocket.State <> wsClosed then
                FDataSocket.Close;
            if FHighLevelFlag and (FStatusCodeSave >= 0) then begin
                 FLastResponse := FLastResponseSave;
                 FStatusCode   := FStatusCodeSave;
            end;
            FHighLevelFlag := FALSE;
            FNextRequest   := nil;
            PostMessage(Handle, FMsg_WM_FTP_REQUEST_DONE, 0, ErrCode);
            { if Assigned(FOnRequestDone) then
                FOnRequestDone(Self, FRequestType, ErrCode); }
        end;
    end;
end;


procedure TCustomMtpCli.TriggerResponse;
begin
    if Assigned(FOnResponse) then
        FOnResponse(Self);
end;



procedure TCustomMtpCli.TriggerReadyToTransmit(var bCancel : Boolean);
begin
    if Assigned(FOnReadyToTransmit) then
        FOnReadyToTransmit(Self, bCancel);
end;



function TCustomMtpCli.GetConnected : Boolean;
begin
    Result := FControlSocket.State <> wsClosed;
end;




{* *                                                                     * *}
{* *                              TFtpClient                             * *}
{* *                                                                     * *}


constructor TMtpClient.Create(AOwner: TComponent);
begin
    inherited Create(AOwner);
    FTimeout := 15;
end;



function TMtpClient.Open : Boolean;
begin
    Result := Synchronize(OpenAsync);
end;




function TMtpClient.Connect : Boolean;
begin
    Result := Synchronize(ConnectASync);
end;




function TMtpClient.Get : Boolean;
begin
    Result := Synchronize(GetASync);
end;


function TMtpClient.MtpPort : Boolean;
begin
    Result := Synchronize(PortASync);
end;



function TMtpClient.Put : Boolean;
begin
    Result := Synchronize(PutASync);
end;



function TMtpClient.Quit : Boolean;
begin
    Result := Synchronize(QuitASync);
end;



function TMtpClient.Abort : Boolean;
begin
    Result := Synchronize(AbortASync);
end;



function TMtpClient.Receive : Boolean;
begin
    Result := Synchronize(ReceiveASync);
end;



function TMtpClient.Transmit : Boolean;
begin
    Result := Synchronize(TransmitASync);
end;




function TMtpClient.Progress : Boolean;
begin
    Result := inherited Progress;
    if FTimeout > 0 then
        FTimeStop := LongInt(IcsGetTickCount) + LongInt(FTimeout) * 1000;
end;



function TMtpClient.WaitUntilReady : Boolean;
{$IFDEF MSWINDOWS}
var
    DummyHandle     : THandle;
{$ENDIF}
begin
    FTimeStop := LongInt(IcsGetTickCount) + LongInt(FTimeout) * 1000;
  {$IFDEF MSWINDOWS}
    DummyHandle := INVALID_HANDLE_VALUE;
  {$ENDIF}
    while TRUE do begin
        if FState in [ftpReady {, ftpInternalReady}] then begin
            Result := (FRequestResult = 0);
            break;
        end;

        if Terminated or
           ((FTimeout > 0) and (LongInt(IcsGetTickCount) > FTimeStop)) then begin
            AbortAsync;
            FErrorMessage := '426 Timeout';
            FStatusCode   := 426;
            Result        := FALSE;
            break;
        end;
      {$IFDEF MSWINDOWS}
        if ftpWaitUsingSleep in FOptions then
            Sleep(0)
        else
            MsgWaitForMultipleObjects(0, DummyHandle, FALSE, 1000, QS_ALLINPUT);
      {$ENDIF}
        MessagePump;
    end;
end;



function TMtpClient.Synchronize(Proc : TFtpNextProc) : Boolean;
begin
    try
        Proc;
        Result := WaitUntilReady;
    except
        Result := FALSE;
    end;
end;



end.


