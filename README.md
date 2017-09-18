# iOS-Https适配


  代码中写了两种方式适配https，一种是使用NSURLSession实现https的适配，一种是使用AFNNetworking，过程详细有注释。如果有帮助请点个star，谢谢！
  
  
  下载代码后需要提供两个条件：
  
  
    一：需要在合适的地方提供出公司的https的有效链接；
    二：需要管公司运维要个crt文件（就说适配https用的证书运维就知道了），使用终端转成cer后缀（
    openssl x509 -in 你的证书.crt -out 你的证书.cer -outform der）拖入工程，然后在合适的地方换成cer文件的名字即可！
