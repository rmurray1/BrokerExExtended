program BrokerExampleExtended;

uses
  Forms,
  fBrokerExample in 'fBrokerExample.pas' {frmBrokerExample},
  SplVista,
  Vcl.Themes,
  Vcl.Styles,
  CCOWRPCBrokerH in 'broker\CCOWRPCBrokerH.pas',
  frmSignonMessageH in 'broker\frmSignonMessageH.pas' {frmSignonMsg},
  LoginfrmH in 'broker\LoginfrmH.pas' {frmSignon},
  RpcbErrH in 'broker\RpcbErrH.pas' {frmRpcbError},
  RpcSLoginH in 'broker\RpcSLoginH.pas',
  SelDivH in 'broker\SelDivH.pas' {SelDivForm},
  TrpcbH in 'broker\TrpcbH.pas',
  VCEditH in 'broker\VCEditH.pas' {frmVCEdit},
  VWHash in 'broker\VWHash.pas',
  WsockcH in 'broker\WsockcH.pas';

// include to display Vista splash

{$R *.RES}

begin
  //TStyleManager.TrySetStyle('Windows10');
  //TStyleManager.TrySetStyle('Windows');
  Application.CreateForm(TfrmBrokerExample, frmBrokerExample);
  Application.CreateForm(TfrmSignonMsg, frmSignonMsg);
  Application.CreateForm(TfrmSignon, frmSignon);
  Application.CreateForm(TfrmRpcbError, frmRpcbError);
  Application.CreateForm(TSelDivForm, SelDivForm);
  Application.CreateForm(TfrmVCEdit, frmVCEdit);
  SplashOpen;                                    // display splash screen
  SplashClose(3000);                             // min splash time 3 seconds, then close
  Application.Run;
end.
