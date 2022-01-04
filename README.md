# BypassUserAdd
## Subscription
通过反射DLL注入、Win API、C#、以及底层实现NetUserAdd方式实现BypassAV进行增加用户的功能,实现Cobalt Strike插件化


## Usage
结合cna使用,直接load cna然后选对应的UserAdd方式即可
![](https://md.byr.ac.cn/uploads/upload_c075492f5b1e7340f3f742356f5c7797.png)

## Note

**暂时先只支持x64**

主要实现了四种方式：
- 1. 通过编写反射DLL实现API(NetUserAdd)添加用户
- 2. 通过编写反射DLL实现重新实现NetUserAdd底层封装（主要是利用MS-SAMR）进行用户添加
- 3. 通过微软提供C#利用活动目录创建用户方式,实现内存调用(execute-assembly)  参考:[https://docs.microsoft.com/zh-cn/troubleshoot/dotnet/csharp/add-user-local-system](https://)
- 4. 通过上传重写NetUserAdd底层实现添加用户的可执行程序实现添加用户
