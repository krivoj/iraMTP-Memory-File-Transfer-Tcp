unit Unit1;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs,  iramtpCli, OverbyteIcsWndControl, OverbyteIcsWSocket,
  Vcl.StdCtrls, iraMtpSrv, Vcl.ExtCtrls;

type
  TForm1 = class(TForm)
    MtpClient: TMtpClient;
    Button1: TButton;
    MtpServer: TMtpServer;
    Memo1: TMemo;
    Memo2: TMemo;
    Image1: TImage;
    lbl5: TLabel;
    Image2: TImage;
    Button2: TButton;
    procedure MtpClientBgException(Sender: TObject; E: Exception; var CanClose: Boolean);
    procedure MtpClientDisplay(Sender: TObject; var Msg: string);
    procedure MtpClientError(Sender: TObject; var Msg: string);
    procedure MtpClientResponse(Sender: TObject);
    procedure MtpClientSessionClosed(Sender: TObject; ErrCode: Word);
    procedure MtpClientSessionConnected(Sender: TObject; ErrCode: Word);
    procedure MtpClientStateChange(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure MtpServerBgException(Sender: TObject; E: Exception; var CanClose: Boolean);
    procedure MtpServerClientCommand(Sender: TObject; Client: TMtpCtrlSocket;  var Keyword, Params, Answer: TFtpString);
    procedure MtpServerClientConnect(Sender: TObject; Client: TMtpCtrlSocket;   AError: Word);
    procedure MtpServerStorSessionClosed(Sender: TObject; Client: TMtpCtrlSocket; Data: TWSocket; AError: Word);
    procedure FormCreate(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure MtpServerDisplay(Sender: TObject; Client: TMtpCtrlSocket;
      Msg: TFtpString);
  private
    { Private declarations }
    procedure DisplayC ( s: string);
    procedure DisplayS ( s: string);
  public
    { Public declarations }
  end;

var
  Form1: TForm1;
  DIR_APP: string;
implementation

{$R *.dfm}
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


procedure TForm1.Button1Click(Sender: TObject);
begin

  MtpClient.StreamSize := image1.Picture.Bitmap.Width * image1.Picture.Bitmap.height * 3  ;
  MtpClient.MemoryName := 'image1';
  MtpClient.MemoryPtr := image1.Picture.Bitmap.ScanLine [image1.Picture.Bitmap.Height -1] ;
  MtpClient.Put ;

end;

procedure TForm1.MtpClientBgException(Sender: TObject; E: Exception;  var CanClose: Boolean);
begin
  displayC ('exc ' + e.Message );

end;

procedure TForm1.MtpClientDisplay(Sender: TObject; var Msg: string);
var
Ptr: pointer;
BMP: TBitmap;
begin
  displayC(msg);

  if Msg = '< 226 File sent ok' then begin

    Ptr:=  Image1.Picture.Bitmap.scanline [Image1.Picture.Bitmap.Height -1] ;
    MtpClient.LocalStream.Read  ( Ptr^ , MtpClient.LocalStream.Size  );
    image1.Invalidate ;
  end;

end;

procedure TForm1.MtpClientError(Sender: TObject; var Msg: string);
begin
  DisplayC('error ' + Msg);

end;

procedure TForm1.MtpClientResponse(Sender: TObject);
begin
  DisplayC(MtpClient.LastResponse);

end;

procedure TForm1.MtpClientSessionClosed(Sender: TObject; ErrCode: Word);
begin
   lbl5.Font.Color:= clRed;
   lbl5.Caption := 'Mtp Closed';


end;

procedure TForm1.MtpClientSessionConnected(Sender: TObject; ErrCode: Word);
begin
If ErrCode = 0 then begin
  DisplayC ( 'Connessione a Mtp :OK') ;
  lbl5.Font.Color:= clgreen;
  lbl5.Caption := 'Mtp Connected';
end
 else
    DisplayC ( 'Connessione a Mtp Error:' + IntToStr(Errcode));

end;

procedure TForm1.MtpClientStateChange(Sender: TObject);
begin
  DisplayC(LookupFtpState (MtpClient.State ) );

end;

procedure TForm1.MtpServerBgException(Sender: TObject; E: Exception;   var CanClose: Boolean);
begin
  ShowMessage('except:' + e.Message );

end;

procedure TForm1.MtpServerClientCommand(Sender: TObject; Client: TMtpCtrlSocket;     var Keyword, Params, Answer: TFtpString);
begin
  DisplayS(Keyword + ' ' + params);
  if Keyword = 'RETR' then begin
    Client.DataStream.Position := 0;
    client.DataStream.Size := image2.Picture.Bitmap.Width * image2.Picture.Bitmap.height * 3;
  end;



end;

procedure TForm1.MtpServerClientConnect(Sender: TObject; Client: TMtpCtrlSocket;  AError: Word);
begin
    if MtpServer.ClientCount  >= MtpServer.MaxClients then begin
     Client.CloseDelayed ;
     Exit;
    end;


  DisplayS( 'Mtp: client connesso: ' + Client.peerAddr  );

end;

procedure TForm1.MtpServerDisplay(Sender: TObject; Client: TMtpCtrlSocket;  Msg: TFtpString);
begin
  displayS(Msg);
end;

procedure TForm1.MtpServerStorSessionClosed(Sender: TObject;   Client: TMtpCtrlSocket; Data: TWSocket; AError: Word);
var
Ptr: pointer;
BMP: TBitmap;
begin
  BMP:= Tbitmap.Create ;
  BMP.PixelFormat := pf24bit;
  BMP.Width := image1.picture.Bitmap.Width   ;
  BMP.Height := image1.picture.Bitmap.Height ;
  BMP.Canvas.Brush.Color:= clyellow;
  BMP.Canvas.FillRect(rect(0,0,BMP.Width,BMP.Height ) );
  image2.Picture.Assign(BMP);

  Client.DataStream.Position :=0;
  Ptr:=  Image2.Picture.Bitmap.scanline [Image2.Picture.Bitmap.Height -1] ;
  Client.DataStream.Read  ( Ptr^ , Client.DataStream.size );

  // il server modifica image2 e riscriva il client.datastream
  image2.Picture.Bitmap.Canvas.Font.Size := 24;
  image2.Picture.Bitmap.Canvas.TextOut(150,300 ,'MODIFIED');
  image2.Invalidate ;

  Client.DataStream.Position :=0;
  Client.DataStream.Write  ( Ptr^ , Client.DataStream.size );  // il size del Bitmap è sempre quello


end;

procedure TForm1.Button2Click(Sender: TObject);
begin
  mtpclient.LocalStream.Position :=0;
  mtpClient.Get ;
end;

procedure Tform1.DisplayC ( s: string);
begin
  memo1.lines.add(S);
end;
procedure Tform1.DisplayS ( s: string);
begin
  memo2.lines.add(S);
end;
procedure TForm1.FormCreate(Sender: TObject);
begin
  DIR_APP:= extractfilepath (application.ExeName);
  MtpServer.Start ;


  MtpClient.HostName  := '127.0.0.1';
  MtpClient.Port := 'ftp'; // o qualsiasi numero
  MtpClient.Open;

  memo1.Lines.Clear;
  memo2.Lines.Clear;
end;

end.
