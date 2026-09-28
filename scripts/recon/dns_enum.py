#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批量 DNS 解析工具（A / AAAA / MX / NS / CNAME / TXT），输出 CSV。

用途：被动信息收集。
- 解析出的 A 记录 IP 即资产，建议入库；
- 多域名解析到同一 IP 是同服务器横向线索；
- MX / NS 可发现邮件系统与 DNS 服务商。

依赖：dnspython、系统 dig（可选，作为兜底解析器）。
用法：
  dns_enum.py --domains www.example.com,mail.example.com
  dns_enum.py --input-file domains.txt --record-type MX
  dns_enum.py -d example.com -t ALL -o out.csv --resolvers 114.114.114.114,8.8.8.8
"""

import argparse
import csv
import datetime
import os
import subprocess
import sys

try:
    import dns.exception
    import dns.resolver
except ImportError:  # pragma: no cover
    print("需要 dnspython：pip install dnspython", file=sys.stderr)
    sys.exit(2)

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "CNAME", "TXT"]
DEFAULT_OUTPUT_DIR = os.environ.get("DNS_ENUM_OUTPUT_DIR") or os.getcwd()


def load_domains(args):
    """从 --domains 与 --input-file 汇总域名，去重保序。"""
    raw = []
    if args.domains:
        raw += [d.strip() for d in args.domains.replace(";", ",").split(",") if d.strip()]
    if args.input_file:
        with open(args.input_file, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                s = line.strip()
                if s and not s.startswith("#"):
                    raw.append(s.split()[0])
    seen, uniq = set(), []
    for d in raw:
        d = d.strip().lower().rstrip(".")
        if d and d not in seen:
            seen.add(d)
            uniq.append(d)
    return uniq


def build_resolver(nameservers, timeout):
    resolver = dns.resolver.Resolver(configure=not nameservers)
    if nameservers:
        resolver.nameservers = nameservers
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def resolve_with_dnspython(resolver, domain, rtype):
    """返回 (values, note)。note 用于标注超时/错误。"""
    try:
        answer = resolver.resolve(domain, rtype, raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return [], ""
    except dns.exception.Timeout:
        return [], "timeout"
    except Exception as exc:  # noqa: BLE001 - 汇总为单行标注，避免中断整批
        return [], "error:%s" % type(exc).__name__
    if answer.rrset is None:
        return [], ""
    values = []
    for record in answer:
        text = record.to_text().strip().rstrip(".")
        values.append(text)
    return values, ""


def resolve_with_dig(domain, rtype, timeout):
    """dnspython 不可用时的兜底：调用系统 dig。"""
    try:
        proc = subprocess.run(
            ["dig", "+short", "+time=%d" % max(1, int(timeout)), domain, rtype],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 3,
        )
    except Exception:  # noqa: BLE001
        return [], "dig-failed"
    text = proc.stdout.decode("utf-8", "ignore")
    values = [ln.strip().rstrip(".") for ln in text.splitlines() if ln.strip()]
    return values, ""


def main():
    parser = argparse.ArgumentParser(description="批量 DNS 解析（A/AAAA/MX/NS/CNAME/TXT），输出 CSV")
    parser.add_argument("-d", "--domains", help="逗号分隔的域名列表")
    parser.add_argument("-i", "--input-file", help="域名列表文件（每行一个，与 --domains 可并用）")
    parser.add_argument("-o", "--output-file", help="输出 CSV 路径（默认当前目录 dns_enum_<时间戳>.csv）")
    parser.add_argument("-t", "--record-type", default="ALL", help="A/AAAA/MX/NS/CNAME/TXT/ALL（默认 ALL）")
    parser.add_argument("--resolvers", default="", help="逗号分隔的 DNS 服务器，如 114.114.114.114,8.8.8.8")
    parser.add_argument("--timeout", type=float, default=5.0, help="单条查询超时秒数（默认 5）")
    args = parser.parse_args()

    domains = load_domains(args)
    if not domains:
        print("错误：未提供域名（--domains 或 --input-file）", file=sys.stderr)
        return 2

    rtype_arg = (args.record_type or "ALL").upper()
    types = RECORD_TYPES if rtype_arg == "ALL" else [t.strip().upper() for t in rtype_arg.split(",") if t.strip()]
    bad = [t for t in types if t not in RECORD_TYPES]
    if bad:
        print("错误：不支持的记录类型 %s（可选 %s）" % (",".join(bad), ",".join(RECORD_TYPES)), file=sys.stderr)
        return 2

    nameservers = [ns.strip() for ns in args.resolvers.split(",") if ns.strip()]
    resolver = None
    use_dig = False
    try:
        resolver = build_resolver(nameservers, args.timeout)
    except Exception:  # noqa: BLE001
        use_dig = True

    out_path = args.output_file
    if not out_path:
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        out_path = os.path.join(DEFAULT_OUTPUT_DIR, "dns_enum_%s.csv" % stamp)
    out_dir = os.path.dirname(os.path.abspath(out_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    total = 0
    hits = 0
    with open(out_path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["domain", "record_type", "value", "note"])
        for domain in domains:
            for rtype in types:
                total += 1
                if use_dig:
                    values, note = resolve_with_dig(domain, rtype, args.timeout)
                else:
                    values, note = resolve_with_dnspython(resolver, domain, rtype)
                if not values:
                    if note:
                        writer.writerow([domain, rtype, "", note])
                    continue
                hits += 1
                for value in values:
                    writer.writerow([domain, rtype, value, note])

    print("域名 %d 个，查询 %d 条，命中 %d 条" % (len(domains), total, hits))
    print("结果已写入: %s" % out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
