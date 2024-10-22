program BrokerExample;

uses
  Forms,
  fBrokerExample in 'fBrokerExample.pas' {frmBrokerExample},
  SplVista,
  Vcl.Themes,
  Vcl.Styles;

// include to display Vista splash

{$R *.RES}

begin
  TStyleManager.TrySetStyle('Windows10');
  TStyleManager.TrySetStyle('Windows');
  Application.CreateForm(TfrmBrokerExample, frmBrokerExample);
  SplashOpen;                                    // display splash screen
  SplashClose(3000);                             // min splash time 3 seconds, then close
  Application.Run;
end.
