
### 设置账号密码
添加名为 **USER**、**PWD**、**TOKEN** 的变量，值分别为 **账号（仅支持手机号）**、**密码 **、**PushPlus推送TOKEN **  

> Settings --> Secrets --> New secret

支持多账号，账号之间与密码之间用  *** # *** 分隔，账号与密码的个数要对应, PushPlus TOKEN只需要一个

示例：**USER:13800000000#13800000001**，**PWD:cxkjntm#jntmcxk**，**TOKEN:123456789abcd**   

### (可选)设置消息提醒
[PushPlus](https://www.pushplus.plus/) 微信扫码免费登录，在个人中心页面得到 token 值；
添加名为 **TOKEN** 的变量，值为上面的 token 值。不支持多账号。


## 注意事项

1. 每天运行两次，可自行配置。

2. 可以通过点击 ***Star*** 手动运行一次。

