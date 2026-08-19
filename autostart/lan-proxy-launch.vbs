' lan-proxy-launch.vbs - 开机自启局域网认证代理 (0.0.0.0:3081)，隐藏窗口，日志落盘
Set ws = CreateObject("WScript.Shell")
WScript.Sleep 20000
ws.CurrentDirectory = "D:\DSH\lan-proxy"
ws.Run "cmd /c node server.js >> ""D:\DSH\lan-proxy\logs\lan-proxy.log"" 2>&1", 0, False
