object frmRpcbError: TfrmRpcbError
  Left = 187
  Top = 278
  Anchors = [akTop]
  BorderStyle = bsDialog
  Caption = 'Error!'
  ClientHeight = 126
  ClientWidth = 222
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -6
  Font.Name = 'MS Sans Serif'
  Font.Style = [fsBold]
  OldCreateOrder = True
  Position = poScreenCenter
  OnCreate = FormCreate
  PixelsPerInch = 96
  TextHeight = 13
  object Bevel1: TBevel
    Left = 4
    Top = 4
    Width = 213
    Height = 90
    Margins.Left = 2
    Margins.Top = 2
    Margins.Right = 2
    Margins.Bottom = 2
  end
  object Label1: TLabel
    Left = 17
    Top = 12
    Width = 41
    Height = 13
    Margins.Left = 2
    Margins.Top = 2
    Margins.Right = 2
    Margins.Bottom = 2
    Alignment = taRightJustify
    Caption = 'Action:'
  end
  object Symbol: TImage
    Left = 8
    Top = 8
    Width = 22
    Height = 22
    Margins.Left = 2
    Margins.Top = 2
    Margins.Right = 2
    Margins.Bottom = 2
  end
  object Label2: TLabel
    Left = 24
    Top = 24
    Width = 34
    Height = 13
    Margins.Left = 2
    Margins.Top = 2
    Margins.Right = 2
    Margins.Bottom = 2
    Alignment = taRightJustify
    Caption = 'Code:'
  end
  object Label3: TLabel
    Left = 8
    Top = 41
    Width = 55
    Height = 13
    Margins.Left = 2
    Margins.Top = 2
    Margins.Right = 2
    Margins.Bottom = 2
    Caption = 'Message:'
  end
  object lblAction: TLabel
    Left = 62
    Top = 12
    Width = 5
    Height = 13
    Margins.Left = 2
    Margins.Top = 2
    Margins.Right = 2
    Margins.Bottom = 2
  end
  object lblCode: TLabel
    Left = 62
    Top = 24
    Width = 5
    Height = 13
    Margins.Left = 2
    Margins.Top = 2
    Margins.Right = 2
    Margins.Bottom = 2
  end
  object lblMessage: TLabel
    Left = 41
    Top = 41
    Width = 176
    Height = 50
    Margins.Left = 2
    Margins.Top = 2
    Margins.Right = 2
    Margins.Bottom = 2
    AutoSize = False
  end
  object BitBtn1: TBitBtn
    Left = 77
    Top = 102
    Width = 64
    Height = 24
    Margins.Left = 2
    Margins.Top = 2
    Margins.Right = 2
    Margins.Bottom = 2
    Kind = bkOK
    NumGlyphs = 2
    TabOrder = 0
  end
  object BitBtn3: TBitBtn
    Left = 155
    Top = 102
    Width = 64
    Height = 24
    Margins.Left = 2
    Margins.Top = 2
    Margins.Right = 2
    Margins.Bottom = 2
    Kind = bkHelp
    NumGlyphs = 2
    TabOrder = 1
  end
end
