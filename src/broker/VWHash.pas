{ **************************************************************
	Package: XWB - Kernel RPCBroker
	Date Created: Sept 18, 1997 (Version 1.1)
	Site Name: Oakland, OI Field Office, Dept of Veteran Affairs
	Developers: Wally Fort, Joel Ivey
	Description: Contains TRPCBroker and related components.
  Unit: XWBHash encryption and decryption functions.
	Current Release: Version 1.1 Patch 65
*************************************************************** }

{ **************************************************
  Changes in v1.1.65 (HGW 10/12/2016) XWB*1.1*65
  1. Renamed unit Hash to XWBHash due to conflict with System.Hash unit in
     Delphi XE8.

  Changes in v1.1.60 (HGW 12/18/2013) XWB*1.1*60
  1. None.

  Changes in v1.1.50 (JLI 09/01/2011) XWB*1.1*50
  1. None.
************************************************** }
unit VWHash;

{
Copyright 2016 Department of Veterans Affairs

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
}
{
  Modified to support OSEHRA and "VA Demo" hash tables
}

interface

uses
  SysUtils, Classes;

{function and procedure prototypes}

function Decrypt(EncryptedText: string): string;
function Encrypt(NormalText: string): string;
function HashDecrypt(Hash, EncryptedText: string): string;
function HashEncrypt(Hash, NormalText: string): string;

function setCipherPad(aPad: Array of string): Integer;
procedure setCipherPadDefault;

const
  maxKeys = 20;

var
  CipherPad: array[0..maxKeys - 1] of string;

const
{ VistA hash table. Used by default ------------------------------------- begin}
  vistaCipherPad: array[0..maxKeys - 1] of string = (

    'wkEo-ZJt!dG)49K{nX1BS$vH<&:Myf*>Ae0jQW=;|#PsO`''%+rmb[gpqN,l6/hFC@DcUa ]z~R}"V\iIxu?872.(TYL5_3',
    'rKv`R;M/9BqAF%&tSs#Vh)dO1DZP> *fX''u[.4lY=-mg_ci802N7LTG<]!CWo:3?{+,5Q}(@jaExn$~p\IyHwzU"|k6Jeb',
    '\pV(ZJk"WQmCn!Y,y@1d+~8s?[lNMxgHEt=uw|X:qSLjAI*}6zoF{T3#;ca)/h5%`P4$r]G''9e2if_>UDKb7<v0&- RBO.',
    'depjt3g4W)qD0V~NJar\B "?OYhcu[<Ms%Z`RIL_6:]AX-zG.#}$@vk7/5x&*m;(yb2Fn+l''PwUof1K{9,|EQi>H=CT8S!',
    'NZW:1}K$byP;jk)7''`x90B|cq@iSsEnu,(l-hf.&Y_?J#R]+voQXU8mrV[!p4tg~OMez CAaGFD6H53%L/dT2<*>"{\wI=',
    'vCiJ<oZ9|phXVNn)m K`t/SI%]A5qOWe\&?;jT~M!fz1l>[D_0xR32c*4.P"G{r7}E8wUgyudF+6-:B=$(sY,LkbHa#''@Q',
    'hvMX,''4Ty;[a8/{6l~F_V"}qLI\!@x(D7bRmUH]W15J%N0BYPkrs&9:$)Zj>u|zwQ=ieC-oGA.#?tfdcO3gp`S+En K2*<',
    'jd!W5[];4''<C$/&x|rZ(k{>?ghBzIFN}fAK"#`p_TqtD*1E37XGVs@0nmSe+Y6Qyo-aUu%i8c=H2vJ\) R:MLb.9,wlO~P',
    '2ThtjEM+!=xXb)7,ZV{*ci3"8@_l-HS69L>]\AUF/Q%:qD?1~m(yvO0e''<#o$p4dnIzKP|`NrkaGg.ufCRB[; sJYwW}5&',
    'vB\5/zl-9y:Pj|=(R''7QJI *&CTX"p0]_3.idcuOefVU#omwNZ`$Fs?L+1Sk<,b)hM4A6[Y%aDrg@~KqEW8t>H};n!2xG{',
    'sFz0Bo@_HfnK>LR}qWXV+D6`Y28=4Cm~G/7-5A\b9!a#rP.l&M$hc3ijQk;),TvUd<[:I"u1''NZSOw]*gxtE{eJp|y (?%',
    'M@,D}|LJyGO8`$*ZqH .j>c~h<d=fimszv[#-53F!+a;NC''6T91IV?(0x&/{B)w"]Q\YUWprk4:ol%g2nE7teRKbAPuS_X',
    '.mjY#_0*H<B=Q+FML6]s;r2:e8R}[ic&KA 1w{)vV5d,$u"~xD/Pg?IyfthO@CzWp%!`N4Z''3-(o|J9XUE7k\TlqSb>anG',
    'xVa1'']_GU<X`|\NgM?LS9{"jT%s$}y[nvtlefB2RKJW~(/cIDCPow4,>#zm+:5b@06O3Ap8=*7ZFY!H-uEQk; .q)i&rhd',
    'I]Jz7AG@QX."%3Lq>METUo{Pp_ |a6<0dYVSv8:b)~W9NK`(r''4fs&wim\kReC2hg=HOj$1B*/nxt,;c#y+![?lFuZ-5D}',
    'Rr(Ge6F Hx>q$m&C%M~Tn,:"o''tX/*yP.{lZ!YkiVhuw_<KE5a[;}W0gjsz3]@7cI2\QN?f#4p|vb1OUBD9)=-LJA+d`S8',
    'I~k>y|m};d)-7DZ"Fe/Y<B:xwojR,Vh]O0Sc[`$sg8GXE!1&Qrzp._W%TNK(=J 3i*2abuHA4C''?Mv\Pq{n#56LftUl@9+',
    '~A*>9 WidFN,1KsmwQ)GJM{I4:C%}#Ep(?HB/r;t.&U8o|l[''Lg"2hRDyZ5`nbf]qjc0!zS-TkYO<_=76a\X@$Pe3+xVvu',
    'yYgjf"5VdHc#uA,W1i+v''6|@pr{n;DJ!8(btPGaQM.LT3oe?NB/&9>Z`-}02*%x<7lsqz4OS ~E$\R]KI[:UwC_=h)kXmF',
    '5:iar.{YU7mBZR@-K|2 "+~`M%8sq4JhPo<_X\Sg3WC;Tuxz,fvEQ1p9=w}FAI&j/keD0c?)LN6OHV]lGy''$*>nd[(tb!#');
{ VistA hash table -------------------------------------------------------- end}

{ OSEHRA hash table ----------------------------------------------------- begin}
  osehraCipherPad: array[0..maxKeys - 1] of string = (

    'VEB_0|=f3Y}m<5i$`W>znGA7P:O%H69[2r)jKh@uo\wMb*Da !+T?q4-JI#d;8ypUQ]g"~''&Cc.LNt/kX,e{vl1FRZs(xS',
    'D/Jg><p]1W6Rtqr.QYo8TBEMK-aAIyO(xG7lPz;=d)N}2F!U ,e0~$fk"j[m*3s5@XnZShv+`b''{u&_\9%|wL4ic:V?H#C',
    '?lBUvZq\fwk+u#:50`SOF9,dp&*G-M=;{8Ai6/N7]bQ1szC!(PxW_YV~)3Lm.EIXD2aT|hKj$rnR@["c g''<>t%4oJHy}e',
    'MH,t9K%TwA17-Bzy+XJU?<>4mo @=6:Ipfnx/Y}R8Q\aN~{)VjEW;|Sq]rl[0uLFd`g5Z#e!3$b"P_.si&G(2''Cvkc*ODh',
    'vMy>"X?bSLCl)''jhzHJk.fVc6#*[0OuP@\{,&r(`Es:K!7wi$5F; DoY=p%e<t}4TQA2_W9adR]gNBG1~nIZ+3x-Um|8q/',
    ':"XczmHx;oA%+vR$Mtr CBTU_w<uEK5f,SW*d8OaFGh]j''{7-~Qp#yqP>09si|VY1J!/[lN23&L4`=.D6)ZIb\n?}(ek@g',
    'j7Qh[YU.u6~xm<`vfe%_g-MRF(#iK=trl}C)>GEDN *$OdHzBA98aLJ|2WP:@ko0wy4I/S&,q'']5!13XcVs\?Zp"+{;Tbn',
    '\UVZ;.&]%7fGq`*SA=Kv/-Xr1OBHiwhP5ukYo{2"}d |NsT,>!x6y~cz[C)pe8m9LaRI(MEFlt:Qg#D''n$W04b@_+?j<3J',
    'MgSvV"U''dj5Yf6K*W)/:z$oi7GJ|t(1Ak=ZC,@]Q0?8DnbE[+L`{mq>;aOR}wcB4sF_e9rh2l\x<. PyNpu%IT!&3#HX~-',
    'rFkn4Z0cH7)`6Xq|yL #wmuW?Gf!2YES;.B_D=el}hN[M&x(*AasU9otd+{]g>TQjp<:v%5O"zI\@$Rb~8i-3/''V1,CJPK',
    '\''%u+W)mK41L#:A6!;7("tnyRlaOe09]3EFd ITf.`@P[Q{B$_iYhZo*kbc|HUgz=D>Svr8x,X~-<NsjM}C/&J?p2wV5qG',
    'QCl_329e+DTp&\?jNys V]k*M"X!$Y6[i@g>{RvF''01(45LJZU,:-uAwtB;7|%fx.n`IhSE<OoW~=bdP#/KHzrc)8mG}aq',
    '!{w*PR[B9Oli~T, rFc"/?ast8=)-_Dgo<E#n4HYA%f''N;0@S7pJ`kGIedM|+C2yjvL5b3K6\Z]V(.h}umxz>XQ$qUW:1&',
    '}:SHZ|O~A-bcyJ4%''5vM+ ;eo.$B)Vp\,kTDz1sGL`]*=mg2nxYPd&lErN3[8qF0@u"a_>wQKI{f6C7?9RX(t#i/U<j!Wh',
    ',ry*|7<1keO:Wi C/zh4IZ>x!F[_("Dbu%Hl5Pg=]QG.LKcJ0&ont@+{;ATX6jMwBv?2#f`q\}VYm''8Es$NpU)dR~S9a3-',
    'h,=/:pJ$@mlY-`bwQ)e3Xt8.RUSMV 2A;j[PN}TE9x~kL&<ns5q>_#c1%K+rIuFoa(zyDWdH]?\GB0g*4f6"Z!''v{7|OiC',
    '/$*b.ts0vOx_-o"l3MHI~}!E`eJimPd>Sn&wzFUh?Kf4)g5X<,8pD:9LA{a[k;''|GyYQ=R2B\#q+cru6N1W@(C TV]7Z%j',
    'qEoC?YWNtV{Brg,I(i:e7Jd#6m!D8XT"n[$~1*ZcxL.Kh2s4%Q&ju\5Gvazw+9pF@k`HA)=U3/< -}''0b;|PfSRl_MO]y>',
    '`@X:!R[\tY5OBcZPh$rM_a-"vgJG%|}oIH)wWQ*jDVxlp,''+S zu(&7?>KCn4y1dE02q6b<;F=8]9NAmT{Li3f/esUk.~#',
    '\Zr'';/SMsG76Lj$aBc[#k>u=_O@2J&X{Aft xV4~vz8Q}q)0K.NIpRnYwDhg+<"H-!(PF:m*]?,WCT|dE9o53%`liUey1b');
{ OSEHRA hash table ------------------------------------------------------- end}

{ VA Demo hash table ---------------------------------------------------- begin}
  vademoCipherPad: array[0..maxKeys - 1] of string = (

    '&Qu9l) Jjk|1O+NpA=3*Lbv[(XF,zZWHgi>S"UM;0@.dIon}4_Pw-8qyC?K/YV6t7sE]f~x''D`TB%R#a{\!G<2$h5rc:me',
    '-tFWg@0D[T2{MZLb/o8y.Jp3Oh7w:knRmqV~Xu#E]GYC+''!rP(4|ScBU"Nv*}z&da6j<e$H,xKA9\; s>?%`51I=il_fQ)',
    '1ZsHoTnY;av~%0O+hX,gx[?qCFA/:6{V7|y*f}]258)4GUNl-Q_@r#cPW>$w kB3D"K(iLJ=!E''S<MRe&p.mjI\d`u9tzb',
    'J02b7|*p>`WlOm6qI1Q\Me&)i.ETGwH"RLVu{oBv=P?8+X-j%A!(<]Z,gkh4FDc$}K9n5YC#af;x3/Uty~_N@''rS[sz: d',
    '>uKF}QpBl;~A2DVO=eY</Em&onT.j#+,058"a$k!WN:7LM@\hGv]-3_41`''*y?UPwCZX% xIq{(fti)r9HSgRJb6cd|sz[',
    ']z>}GUqT.K4ePp#;Msf"FHc8[J$I2%Sx-~3EurkgBV?\*iW|&_@=YZ 5b7/<9,`0:NyRaQlhv)X1Do6''({!mLjAtCO+nwd',
    '6Bv>kYgj_GJFE`q]!H27usXz5ZxR%p.Kh{)tUe:~=LV@/[Sw1<Ob$#,8daoT\4cri?Al+Nn3IPmMy9*0"QW|''CfD&;}- (',
    '_}+Fkea1<Z,SDh~ `Y62BHuN-JqO>5j(xsl3*!{G"T&M[/wW4PpiCLtUI9bm:r%fRV.@dQE0A]c\$o|y7;8g?)#=Kz''vnX',
    'TZlp]~x%8,E.}|kMH9/!3a z`yWed0Ccm\jB#SgOfIJ&_(6s{K"@L);>P5<uYD2+nvVRb:''$?XNioqA17-rU=wFt*Gh[4Q',
    '{.= Kt&vz8_`D;+BYc-GkQ"[gJd|]oInwyT''l>)e:XN3UVahiS0!9PqE$L?HA4,R/Mm2W~<*6pjrF#@uZ}5%7xbs(Of1\C',
    'f6\W:mYiF.$"hR<XqE4_sdk-3T,yO#Ix}`r''n /C)tp9{=NBljLKgvuc[P&!>]VU~20zD+1A5H8%SGQ?@*(Zb|o7JM;aew',
    ']''x[m!8OPYLQosE tw{$HuZv"*Gh;7N2.D~Ji3<%e)@a0fBU&dCR1A+=Mn\p|jzTyK`#/S_br:-V>FI96,}cq4l5?WXgk(',
    'A{;0d/H$jg.Niy!:''tcah`&z\*"GTeO=MFI~Z5vbu>m_9)C}6Ps73%x]w[?Xrf+QKRqWB|<4EY8DSn1kL oV-@2#lU(Jp,',
    'Aot4N!@''r/{Rk_<EC"B8l +6)YFz?ID:evMJ[SpZXPs9>f0\caKwU]%*y}GH,m7QdhT&b1V~-L5Ogx|qju=$`32(.Win;#',
    '-xZ\h3_$9.7f>Be!*sT w"UAJ4{q[0mybrENS<dP&]~2i8Ia''MjcKYu;:Rn=G/)t?1W+#%5Q|l(v6pFO`D@V,oCkgzX}LH',
    'mkU3n g/96z>Hx`C"fl5e#uw}Krj7_o*J+vbNR)h\XyOVZ@tE{QTM|]8;c?$PaBW:40,1dY%FG!L[i~D(A.2p=-S''&<sqI',
    'pnRq(hW1)`Xt7D=9PaT*8<d+3/vIEQrcb-gBjYH]MSU#Nwis5.om_%Cu>}6~x{;|!FA\y ekKl,O&[''?VG0:2@LZ$fJ4"z',
    'RJfF>=}:0@(8tW-Aid6h*{/,)ON_B"MZHo.?I]Eek<yL5v3$`c[x~74aYqnDuz1bp+\2smlVCQSP#G&j;X9r%g'' w!|TKU',
    'o*B~e]p0lRY[=/`7CnfO''Wb2+sd3a,6#k{&LU(".qMNG$A%mg:J?Dwc!x5XvS;yj4t<uP@h_KT98 }\H1ZQ-rFi|I)>zVE',
    'E7UvoK3Z%-y$2]s?}mBLQ!OVN''d58&+rk4;_ >u#/1PIt@<~x[G`WA"CMiq|pj=,:a)glXJn0RbwFfDz*e(\H9hc6.{TSY');
{ VA Demo hash table ------------------------------------------------------ end}

implementation

function Translate(passedString, identifier, associator: string): string;
{ TRANSLATE(string,identifier,associator)
  Performs a character-for-character replacement within a string. }
var
  index, position: integer;
  newString: string;
  substring: string;

begin
  newString := ''; { initialize NewString }
  for index := 1 to length(passedString) do
  begin
    substring := copy(passedString, index, 1);
    position := pos(substring, identifier);
    if position > 0 then
      newString := newString + copy(associator, position, 1)
    else
      newString := newString + copy(passedString, index, 1)
  end;
  result := newString;
end;

function Encrypt(normalText: string): string;
var
  associatorIndex, identifierIndex: integer;
begin
  Randomize;
  associatorIndex := random(MaxKeys);
  repeat
    identifierIndex := Random(MaxKeys);
  until associatorIndex <> identifierIndex; {make sure indexes are different}

  Result := chr(AssociatorIndex+32) +
            Translate(NormalText, CipherPad[AssociatorIndex],
                      CipherPad[IdentifierIndex]) +
            chr(identifierIndex+32);
end;

function Decrypt(EncryptedText: string): string;
var
  AssociatorIndex, IdentifierIndex: integer;
begin
  IdentifierIndex := Ord(EncryptedText[1])-32;
  AssociatorIndex := Ord(EncryptedText[Length(EncryptedText)])-32;
  Result := Translate(copy(EncryptedText,2,Length(EncryptedText)-2),
                      CipherPad[AssociatorIndex],
                      CipherPad[IdentifierIndex]);
end;

// set Cipher table
function setCipherPad(aPad:Array of string): Integer;
var
  iCount,
  i: integer;
begin
  Result := Length(aPad) - maxKeys;

  iCount := Length(aPad);
  if iCount > maxKeys then
    iCount := maxKeys;

  for i := 0 to iCount - 1 do
    CipherPad[i] := aPad[i];
end;

// VistA hash table is used by default
procedure setCipherPadDefault;
begin
  setCipherPad(vistaCipherPad);
end;

procedure setPad(aHash: String);
begin
  if (aHash = 'OSEHRA') then
    setCipherPad(osehraCipherPad)
  else if (Uppercase(aHash) = 'VA DEMO') then
    setCipherPad(vademoCipherPad)
  else
    setCipherPad(vistaCipherPad);
end;

function HashDecrypt(Hash, EncryptedText: string): string;
begin
  setPad(Hash);
  Result := Decrypt(EncryptedText);
end;

function HashEncrypt(Hash, NormalText: string): string;
begin
  setPad(Hash);
  Result := Encrypt(NormalText);
end;

initialization

setCipherPadDefault;

end.
