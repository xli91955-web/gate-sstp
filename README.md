# VPN Gate SSTP 检测与订阅源

上游来源：[hezhanleiok/gate](https://github.com/hezhanleiok/gate)。此版本增加真实定时任务、私有检测鉴权、严格成功判断、未知分类和空结果发布保护。

每小时 UTC 第 7、37 分钟运行。GitHub 定时任务可能延迟。节点来自 VPN Gate 志愿者公开中继；住宅标签是运营商估算，不代表长期在线或独享出口。

仓库变量 `CHECK_WORKER` 填自己的 `https://检测Worker/check?sstp=vpn:vpn@`，`EDGE_HOSTS` 填已验证的 `入口域名:443`。仓库 Secret `CHECK_TOKEN` 对应检测 Worker 的 Secret。Pages 设置选择 GitHub Actions。

运行 `pip install -r requirements.txt` 和 `python -m unittest discover -s tests -v` 验证。完整检测成功才发布 `public/`；零成功将阻止部署，保留最后一次页面。

`nodes.txt` 为 edgetunnel 自定义优选 IP 输入，格式 `入口域名:443#名称$sstp://vpn:vpn@节点:端口`。它不是 Clash YAML，也不是 v2rayN 订阅。
