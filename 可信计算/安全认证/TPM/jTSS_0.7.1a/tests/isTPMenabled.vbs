' This script tests if the TPM is recognized by Vista TBS and enabled.
' This script requires Administrator privileges to succeed.
' (c) IAIK Graz Univeristy of Technology 2008
' contact: ronald.toegl@iaik.tugraz.at

Option Explicit
On error Resume Next
Err.Clear

Dim oTpmService, oTpm, isenabled
isenabled=false

' Create the Win32_Tpm object
Set oTpmService = GetObject("winmgmts:{impersonationLevel=impersonate," _
                              & "authenticationLevel=pktPrivacy}!\\" _
                              & "." _
                              & "\Root\CIMV2\Security\MicrosoftTpm")
Set oTpm = oTpmService.Get("Win32_Tpm=@")

oTpm.IsEnabled isenabled     

If  isenabled = False or Err.Number <> 0 Then
  MsgBox   "Error: The TPM services of Windows Vista are not available.  Apparently, the TPM is not enabled or not recognized by Windows Vista. Note, that a hardware version 1.2 TPM is required and that you also need to enable it it in the BIOS before you can use it. Also you must be an Administrator to execute setup. jTSS setup quits.", vbCritical, "jTSS Setup: Test TPM Status"
  WScript.Quit(1)
Else  
      'MsgBox  "The TPM is enabled"
      WScript.Quit(0)
End If 