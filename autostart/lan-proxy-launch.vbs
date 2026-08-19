' lan-proxy-launch.vbs - 开机自启局域网认证代理 (0.0.0.0:3081)，隐藏窗口，日志落盘
' 开源模板：以下为示例路径，请按你的实际部署目录修改后再放入启动文件夹
Set ws = CreateObject("WScript.Shell")
WScript.Sleep 20000
ws.CurrentDirectory = "D:\lan-proxy"
ws.Run "cmd /c node server.js >> ""D:\lan-proxy\logs\lan-proxy.log"" 2>&1", 0, False
