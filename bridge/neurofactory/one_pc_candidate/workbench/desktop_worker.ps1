# NEIROZAVOD ONE: unprivileged Windows desktop I/O worker.
# Read-only by default; commands come over a local stdio pipe, NOT the network.
# Exact foreground process and window handle are verified before every action.
$ErrorActionPreference = "Stop"
# Python local controller uses UTF-8 JSON over stdin/stdout. PowerShell 5.1
# otherwise defaults to OEM/ANSI and corrupts Cyrillic keyboard input.
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class NFDesktop {
  [StructLayout(LayoutKind.Sequential)] public struct RECT {
    public int Left, Top, Right, Bottom;
  }
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a,uint b,bool attach);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(
      IntPtr hWnd, out uint processId);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(
      IntPtr hWnd, out RECT rect);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x,int y);
  [DllImport("user32.dll")] public static extern void mouse_event(
      uint flags,uint x,uint y,uint data,IntPtr extra);
  [StructLayout(LayoutKind.Sequential)] public struct INPUT {
    public uint type;
    public INPUTUNION data;
  }
  [StructLayout(LayoutKind.Explicit)] public struct INPUTUNION {
    [FieldOffset(0)] public MOUSEINPUT mi;
    [FieldOffset(0)] public KEYBDINPUT ki;
  }
  [StructLayout(LayoutKind.Sequential)] public struct MOUSEINPUT {
    public int dx,dy;
    public uint mouseData,dwFlags,time;
    public UIntPtr extraInfo;
  }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT {
    public ushort wVk,wScan;
    public uint dwFlags,time;
    public UIntPtr extraInfo;
  }
  [DllImport("user32.dll", SetLastError=true)]
  public static extern uint SendInput(uint count, INPUT[] input, int size);
  public static bool TypeUnicode(string text) {
    INPUT[] inputs = new INPUT[text.Length*2];
    int idx=0;
    foreach(char c in text) {
      INPUT down=new INPUT(); down.type=1;
      down.data.ki.wVk=0; down.data.ki.wScan=(ushort)c;
      down.data.ki.dwFlags=4;
      INPUT up=down; up.data.ki.dwFlags=6;
      inputs[idx++]=down; inputs[idx++]=up;
    }
    if(inputs.Length==0) return false;
    return SendInput((uint)inputs.Length,inputs,Marshal.SizeOf(typeof(INPUT)))
      ==inputs.Length;
  }
}
'@
if (-not [Environment]::UserInteractive -or
    [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) {
  [Console]::Out.WriteLine('{"id":0,"ok":false,"error":"DESKTOP_INTERACTIVE_SESSION_REQUIRED"}')
  exit 2
}
function Foreground {
  $h=[NFDesktop]::GetForegroundWindow()
  if($h -eq [IntPtr]::Zero){throw "DESKTOP_NO_FOREGROUND"}
  [uint32]$processId=0
  [void][NFDesktop]::GetWindowThreadProcessId($h,[ref]$processId)
  if($processId -le 0){throw "DESKTOP_FOREGROUND_INVALID"}
  $proc=Get-Process -Id $processId -ErrorAction Stop
  if($proc.SessionId -ne [Diagnostics.Process]::GetCurrentProcess().SessionId){
    throw "DESKTOP_DIFFERENT_USER_SESSION"
  }
  if(-not $proc.Path){throw "DESKTOP_PATH_UNKNOWN"}
  $r=New-Object NFDesktop+RECT
  if(-not [NFDesktop]::GetWindowRect($h,[ref]$r)){throw "DESKTOP_WINDOW_RECT_INVALID"}
  $app=[IO.Path]::GetFileName($proc.Path).ToLowerInvariant()
  $width=$r.Right-$r.Left; $height=$r.Bottom-$r.Top
  if($width -lt 40 -or $height -lt 40 -or $width -gt 4096 -or $height -gt 2160){
    throw "DESKTOP_WINDOW_BOUNDS_REFUSED"
  }
  return @{handle=$h.ToInt64();pid=[int]$processId;app=$app;
           x=$r.Left;y=$r.Top;width=$width;height=$height}
}
function WindowFromProcess([int]$expectedProcessId,[long]$handle,[string]$app) {
  try{$proc=Get-Process -Id $expectedProcessId -ErrorAction Stop}
  catch{throw "DESKTOP_TARGET_PROCESS_GONE"}
  if($proc.SessionId -ne [Diagnostics.Process]::GetCurrentProcess().SessionId){
    throw "DESKTOP_DIFFERENT_USER_SESSION"
  }
  $procApp=[IO.Path]::GetFileName($proc.Path).ToLowerInvariant()
  if($procApp -cne $app -or $proc.MainWindowHandle.ToInt64() -ne $handle){
    throw "DESKTOP_TARGET_CHANGED"
  }
  $r=New-Object NFDesktop+RECT
  if(-not [NFDesktop]::GetWindowRect([IntPtr]$handle,[ref]$r)){
    throw "DESKTOP_WINDOW_RECT_INVALID"
  }
  $width=$r.Right-$r.Left;$height=$r.Bottom-$r.Top
  if($width -lt 40 -or $height -lt 40 -or $width -gt 4096 -or $height -gt 2160){
    throw "DESKTOP_WINDOW_BOUNDS_REFUSED"
  }
  return @{app=$app;pid=$expectedProcessId;handle=$handle;x=$r.Left;
           y=$r.Top;width=$width;height=$height}
}
function AssertForeground($req) {
  $w=WindowFromProcess ([int]$req.pid) ([long]$req.handle) ([string]$req.app)
  if([NFDesktop]::GetForegroundWindow().ToInt64() -ne $w.handle){
    [void][NFDesktop]::SetForegroundWindow([IntPtr]$w.handle)
    Start-Sleep -Milliseconds 90
  }
  if([NFDesktop]::GetForegroundWindow().ToInt64() -ne $w.handle){
    # WScript AppActivate uses the ordinary interactive user's shell,
    # not a privilege elevation or a hidden desktop.
    try{
      $shell=New-Object -ComObject WScript.Shell
      [void]$shell.AppActivate([int]$w.pid)
      Start-Sleep -Milliseconds 160
    }catch {}
  }
  if([NFDesktop]::GetForegroundWindow().ToInt64() -ne $w.handle){
    # Owner-approved application activation within the same interactive
    # desktop. No secure-desktop/UAC crossover or process injection.
    $other=[NFDesktop]::GetForegroundWindow()
    [uint32]$otherId=0
    $otherThread=[NFDesktop]::GetWindowThreadProcessId($other,[ref]$otherId)
    $mine=[NFDesktop]::GetCurrentThreadId()
    $attached=$false
    try {
      if($otherThread -gt 0 -and $otherThread -ne $mine){
        $attached=[NFDesktop]::AttachThreadInput($mine,$otherThread,$true)
      }
      [void][NFDesktop]::SetForegroundWindow([IntPtr]$w.handle)
      Start-Sleep -Milliseconds 100
    } finally {
      if($attached){[void][NFDesktop]::AttachThreadInput($mine,$otherThread,$false)}
    }
  }
  if([NFDesktop]::GetForegroundWindow().ToInt64() -ne $w.handle){
    throw "DESKTOP_FOREGROUND_ACTIVATION_DENIED"
  }
  return $w
}
function ClampXY($req,$w){
  if($req.x -isnot [long] -and $req.x -isnot [int]){throw "DESKTOP_POINT_INVALID"}
  if($req.y -isnot [long] -and $req.y -isnot [int]){throw "DESKTOP_POINT_INVALID"}
  $x=[int]$req.x;$y=[int]$req.y
  if($x -lt 0 -or $y -lt 0 -or $x -ge $w.width -or $y -ge $w.height) {
    throw "DESKTOP_POINT_OUTSIDE_WINDOW"
  }
  return @{x=$w.x+$x;y=$w.y+$y}
}
function Capture($w) {
  $screen=[Windows.Forms.SystemInformation]::VirtualScreen
  $left=[Math]::Max($w.x,$screen.Left)
  $top=[Math]::Max($w.y,$screen.Top)
  $right=[Math]::Min($w.x+$w.width,$screen.Right)
  $bottom=[Math]::Min($w.y+$w.height,$screen.Bottom)
  $width=$right-$left;$height=$bottom-$top
  if($width -lt 30 -or $height -lt 30 -or $width -gt 1600 -or $height -gt 1000) {
    throw "DESKTOP_CAPTURE_BOUNDS_REFUSED"
  }
  $bmp=New-Object Drawing.Bitmap($width,$height)
  try {
    $graphics=[Drawing.Graphics]::FromImage($bmp)
    try {$graphics.CopyFromScreen($left,$top,0,0,$bmp.Size)}
    finally {$graphics.Dispose()}
    $mem=New-Object IO.MemoryStream
    try {
      $bmp.Save($mem,[Drawing.Imaging.ImageFormat]::Jpeg)
      if($mem.Length -gt 600000){throw "DESKTOP_CAPTURE_TOO_LARGE"}
      return @{image=[Convert]::ToBase64String($mem.ToArray());width=$width;height=$height;
               offset_x=$left-$w.x;offset_y=$top-$w.y}
    } finally {$mem.Dispose()}
  } finally {$bmp.Dispose()}
}
function AssertEditor($expectedProcessId) {
  $focus=[Windows.Automation.AutomationElement]::FocusedElement
  if($null -eq $focus){throw "DESKTOP_EDITOR_NOT_FOUND"}
  if($focus.Current.ProcessId -ne $expectedProcessId){throw "DESKTOP_EDITOR_OTHER_PROCESS"}
  if($focus.Current.IsPassword){throw "DESKTOP_PASSWORD_FIELD_DENIED"}
  $type=$focus.Current.ControlType
  if($type -ne [Windows.Automation.ControlType]::Edit -and
     $type -ne [Windows.Automation.ControlType]::Document){
    throw "DESKTOP_TEXT_INPUT_NOT_FOCUSED"
  }
  $pattern=$null
  if($focus.TryGetCurrentPattern([Windows.Automation.ValuePattern]::Pattern,[ref]$pattern)){
    if($pattern.Current.IsReadOnly){throw "DESKTOP_READ_ONLY_FIELD"}
  }
}
while($true){
  $line=[Console]::ReadLine()
  if($null -eq $line){break}
  try{
    if($line.Length -gt 11000){throw "DESKTOP_REQUEST_TOO_LARGE"}
    $req=$line|ConvertFrom-Json
    if($null -eq $req -or $null -eq $req.id){throw "DESKTOP_INVALID_REQUEST"}
    $result=$null
    switch([string]$req.op){
      "list" {
        $windows=@()
        foreach($pr in @(Get-Process | Where-Object {
            $_.MainWindowHandle -ne 0 -and
            $_.SessionId -eq [Diagnostics.Process]::GetCurrentProcess().SessionId
        } | Select-Object -First 80)){
          try {
            if(-not $pr.Path){continue}
            $w=WindowFromProcess ([int]$pr.Id) ([long]$pr.MainWindowHandle.ToInt64()) ([IO.Path]::GetFileName($pr.Path).ToLowerInvariant())
            $windows+=@{app=$w.app;pid=$w.pid;handle=$w.handle;
                         width=$w.width;height=$w.height}
          } catch {}
        }
        $result=@{windows=$windows}
        break
      }
      "attach" {
        $w=WindowFromProcess ([int]$req.pid) ([long]$req.handle) ([string]$req.app)
        $result=@{app=$w.app;pid=$w.pid;handle=$w.handle;
                  width=$w.width;height=$w.height}
        break
      }
      "inspect" {
        $w=Foreground
        $result=@{app=$w.app;pid=$w.pid;handle=$w.handle;
                  width=$w.width;height=$w.height}
        break
      }
      "frame" {
        $w=AssertForeground $req
        $result=Capture $w
        break
      }
      "move" {
        $w=AssertForeground $req
        $pt=ClampXY $req $w
        if(-not [NFDesktop]::SetCursorPos($pt.x,$pt.y)){throw "DESKTOP_MOVE_DENIED"}
        $result=@{moved=$true}
        break
      }
      "click" {
        $w=AssertForeground $req
        $pt=ClampXY $req $w
        if(-not [NFDesktop]::SetCursorPos($pt.x,$pt.y)){throw "DESKTOP_MOVE_DENIED"}
        [NFDesktop]::mouse_event(2,0,0,0,[IntPtr]::Zero)
        [NFDesktop]::mouse_event(4,0,0,0,[IntPtr]::Zero)
        $result=@{clicked=$true}
        break
      }
      "type" {
        $w=AssertForeground $req
        $inputText=[string]$req.text
        if([string]::IsNullOrWhiteSpace($inputText) -or
           $inputText.Length -gt 500 -or
           $inputText -match '[\x00-\x09\x0b-\x1f\x7f]'){
          throw "DESKTOP_TEXT_INVALID"
        }
        AssertEditor $w.pid
        if(-not [NFDesktop]::TypeUnicode($inputText)){throw "DESKTOP_SEND_INPUT_FAILED"}
        $result=@{typed=$true;characters=$inputText.Length}
        break
      }
      default {throw "DESKTOP_OPERATION_REFUSED"}
    }
    $response=@{id=$req.id;ok=$true;result=$result}
  } catch {
    # Avoid storing or returning untrusted page content and sensitive inputs.
    $err=[string]$_.Exception.Message
    if($err -notmatch '^DESKTOP_[A-Z_]+$'){$err="DESKTOP_ACTION_FAILED"}
    $response=@{id=$req.id;ok=$false;error=$err}
  }
  [Console]::Out.WriteLine(($response|ConvertTo-Json -Compress -Depth 6))
}
