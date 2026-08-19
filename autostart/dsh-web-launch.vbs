' dsh-web-launch.vbs - 开机自启 DSH Web GUI (127.0.0.1:3080)，隐藏窗口，日志落盘
Set ws = CreateObject("WScript.Shell")
WScript.Sleep 10000
ws.CurrentDirectory = "D:\deepseek-harness-master"
ws.Run "cmd /c pnpm dsh web >> ""D:\DSH\lan-proxy\logs\dsh-web.log"" 2>&1", 0, False
