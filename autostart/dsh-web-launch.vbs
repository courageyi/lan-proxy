' dsh-web-launch.vbs - 开机自启 DSH Web GUI (127.0.0.1:3080)，隐藏窗口，日志落盘
' 开源模板：以下为示例路径，请按你的实际部署目录修改后再放入启动文件夹
Set ws = CreateObject("WScript.Shell")
WScript.Sleep 10000
ws.CurrentDirectory = "D:\deepseek-harness"
ws.Run "cmd /c pnpm dsh web >> ""D:\lan-proxy\logs\dsh-web.log"" 2>&1", 0, False
