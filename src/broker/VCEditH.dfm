object frmVCEdit: TfrmVCEdit
  Left = 197
  Top = 197
  Anchors = [akTop]
  Caption = 'Change VistA Verify Code'
  ClientHeight = 126
  ClientWidth = 406
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  TextHeight = 13
  object lblOldVC: TLabel
    Left = 8
    Top = 12
    Width = 110
    Height = 16
    Margins.Left = 2
    Margins.Top = 2
    Margins.Right = 2
    Margins.Bottom = 2
    Caption = '&Old verify code:'
    FocusControl = edtOldVC
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'MS Sans Serif'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object lblNewVC: TLabel
    Left = 7
    Top = 48
    Width = 116
    Height = 16
    Margins.Left = 2
    Margins.Top = 2
    Margins.Right = 2
    Margins.Bottom = 2
    Caption = '&New verify code:'
    FocusControl = edtNewVC
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'MS Sans Serif'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object lblConfirmVC: TLabel
    Left = 8
    Top = 84
    Width = 169
    Height = 16
    Margins.Left = 2
    Margins.Top = 2
    Margins.Right = 2
    Margins.Bottom = 2
    Caption = 'Con&firm new verify code:'
    FocusControl = edtConfirmVC
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'MS Sans Serif'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object edtOldVC: TEdit
    Left = 184
    Top = 12
    Width = 110
    Height = 24
    Margins.Left = 2
    Margins.Top = 2
    Margins.Right = 2
    Margins.Bottom = 2
    Ctl3D = True
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'MS Sans Serif'
    Font.Style = [fsBold]
    ParentCtl3D = False
    ParentFont = False
    PasswordChar = '*'
    TabOrder = 0
    OnChange = edtOldVCChange
  end
  object edtNewVC: TEdit
    Left = 184
    Top = 48
    Width = 110
    Height = 24
    Margins.Left = 2
    Margins.Top = 2
    Margins.Right = 2
    Margins.Bottom = 2
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'MS Sans Serif'
    Font.Style = [fsBold]
    ParentFont = False
    PasswordChar = '*'
    TabOrder = 1
    OnChange = edtOldVCChange
    OnExit = edtNewVCExit
  end
  object edtConfirmVC: TEdit
    Left = 184
    Top = 83
    Width = 110
    Height = 24
    Margins.Left = 2
    Margins.Top = 2
    Margins.Right = 2
    Margins.Bottom = 2
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'MS Sans Serif'
    Font.Style = [fsBold]
    ParentFont = False
    PasswordChar = '*'
    TabOrder = 2
    OnChange = edtOldVCChange
  end
  object btnOK: TBitBtn
    Left = 298
    Top = 7
    Width = 85
    Height = 26
    Margins.Left = 2
    Margins.Top = 2
    Margins.Right = 2
    Margins.Bottom = 2
    Caption = '&OK'
    Glyph.Data = {
      BE060000424DBE06000000000000360400002800000024000000120000000100
      0800000000008802000000000000000000000001000000010000000000000000
      80000080000000808000800000008000800080800000C0C0C000C0DCC000F0CA
      A600000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000F0FBFF00A4A0A000808080000000
      FF0000FF000000FFFF00FF000000FF00FF00FFFF0000FFFFFF00030303030303
      0303030303030303030303030303030303030303030303030303030303030303
      03030303030303030303030303030303030303030303FF030303030303030303
      03030303030303040403030303030303030303030303030303F8F8FF03030303
      03030303030303030303040202040303030303030303030303030303F80303F8
      FF030303030303030303030303040202020204030303030303030303030303F8
      03030303F8FF0303030303030303030304020202020202040303030303030303
      0303F8030303030303F8FF030303030303030304020202FA0202020204030303
      0303030303F8FF0303F8FF030303F8FF03030303030303020202FA03FA020202
      040303030303030303F8FF03F803F8FF0303F8FF03030303030303FA02FA0303
      03FA0202020403030303030303F8FFF8030303F8FF0303F8FF03030303030303
      FA0303030303FA0202020403030303030303F80303030303F8FF0303F8FF0303
      0303030303030303030303FA0202020403030303030303030303030303F8FF03
      03F8FF03030303030303030303030303FA020202040303030303030303030303
      0303F8FF0303F8FF03030303030303030303030303FA02020204030303030303
      03030303030303F8FF0303F8FF03030303030303030303030303FA0202020403
      030303030303030303030303F8FF0303F8FF03030303030303030303030303FA
      0202040303030303030303030303030303F8FF03F8FF03030303030303030303
      03030303FA0202030303030303030303030303030303F8FFF803030303030303
      030303030303030303FA0303030303030303030303030303030303F803030303
      0303030303030303030303030303030303030303030303030303030303030303
      0303}
    NumGlyphs = 2
    TabOrder = 3
    OnClick = btnOKClick
  end
  object btnCancel: TBitBtn
    Left = 298
    Top = 48
    Width = 85
    Height = 26
    Margins.Left = 2
    Margins.Top = 2
    Margins.Right = 2
    Margins.Bottom = 2
    Caption = '&Cancel'
    Kind = bkCancel
    NumGlyphs = 2
    TabOrder = 4
    OnClick = btnCancelClick
  end
  object btnHelp: TBitBtn
    Left = 298
    Top = 84
    Width = 85
    Height = 26
    Margins.Left = 2
    Margins.Top = 2
    Margins.Right = 2
    Margins.Bottom = 2
    Kind = bkHelp
    NumGlyphs = 2
    TabOrder = 5
    OnClick = btnHelpClick
  end
end
