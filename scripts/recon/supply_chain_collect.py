#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""供应链信息收集工具（被动信息收集，基于 FOFA 官方 API）。

用途：从目标公司/主域出发，通过证书反查发现其自签证书关联的供应链域名/IP，
再对每个主域名做子域名资产梳理，最后导出 CSV 汇总。

步骤：
  Step1  cert="<target>"      证书反查 → 发现供应链域名/IP（目标自己签发的证书）
  Step2  domain="<主域名>"     对发现的主域名查子域名资产
  Step3  ip="<关键IP>"         对高价值 IP 查全端口
  Step4  导出 CSV + 去重汇总

依赖：requests。需要 FOFA API Key（--key 或 FOFA_API_KEY 环境变量）。
用法：
  supply_chain_collect.py --target example.com
  supply_chain_collect.py --target example.com --key <FOFA_KEY> -o supply.csv
  supply_chain_collect.py --target 百盛 --cert-exact --size 200
"""

import argparse
import base64
import csv
import datetime
import os
import sys

try:
    import requests
except ImportError:  # pragma: no cover
    print("需要 requests：pip install requests", file=sys.stderr)
    sys.exit(2)

FOFA_ENDPOINT = os.environ.get("FOFA_ENDPOINT", "https://fofa.info/api/v1/search/all")
USER_AGENT = "CyberStrikeAI-supply-chain/1.0"
DEFAULT_FIELDS = "host,ip,port,domain,title,server,icp,cert"


def b64(value):
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def fofa_search(session, key, query, size, fields, timeout):
    """调用 FOFA 搜索，返回 (rows, note)。rows 为 list[dict]。"""
    params = {
        "key": key,
        "qbase64": b64(query),
        "size": size,
        "fields": ",".join(fields),
        "full": "false",
    }
    try:
        resp = session.get(FOFA_ENDPOINT, params=params, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return [], "request-failed:%s" % type(exc).__name__
    if resp.status_code != 200:
        return [], "http-%d" % resp.status_code
    try:
        payload = resp.json()
    except ValueError:
        return [], "bad-json"
    if payload.get("error"):
        return [], "fofa-error:%s" % payload.get("errmsg") or "unknown"
    rows = []
    for item in payload.get("results") or []:
        if isinstance(item, dict):
            rows.append(item)
        elif isinstance(item, list):
            rows.append({fields[i] if i < len(fields) else "col%d" % i: v for i, v in enumerate(item)})
    return rows, ""


def collect_main_domains(rows):
    """从证书反查结果中提取主域名（启发式：取注册域，简化处理为末两段）。"""
    domains = set()
    for row in rows:
        host = str(row.get("host") or "")
        for token in host.replace("https://", "").replace("http://", "").split("/")[0].split(","):
            token = token.strip().split(":")[0]
            if not token or token.replace(".", "").isdigit():
                continue
            parts = token.split(".")
            if len(parts) >= 2:
                domains.add(".".join(parts[-2:]))
    return sorted(domains)


def main():
    parser = argparse.ArgumentParser(description="供应链信息收集（FOFA 证书/域名反查）")
    parser.add_argument("--target", required=True, help="目标关键字，如 example.com / 公司名 / 证书 CN")
    parser.add_argument("--key", default=os.environ.get("FOFA_API_KEY", ""), help="FOFA API Key（默认读 FOFA_API_KEY）")
    parser.add_argument("--cert-exact", action="store_true", help="证书精确匹配 subject_cn（cert.subject_cn=）")
    parser.add_argument("--size", type=int, default=100, help="每步返回条数（默认 100，上限取决于账号）")
    parser.add_argument("-o", "--output", help="输出 CSV 路径（默认当前目录 supply_chain_<时间戳>.csv）")
    parser.add_argument("--timeout", type=float, default=30.0, help="单次请求超时秒数（默认 30）")
    args = parser.parse_args()

    if not args.key:
        print("错误：缺少 FOFA API Key。请用 --key 或设置 FOFA_API_KEY 环境变量。", file=sys.stderr)
        print("提示：可在 FOFA 个人中心获取 key；也可在平台「系统设置 → 资产管理」中填写。", file=sys.stderr)
        return 2

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    fields = DEFAULT_FIELDS.split(",")

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = args.output or os.path.join(os.getcwd(), "supply_chain_%s.csv" % stamp)

    all_rows = []
    step1_query = ('cert.subject_cn="%s"' % args.target) if args.cert_exact else ('cert="%s"' % args.target)
    print("Step1 证书反查: %s" % step1_query)
    rows1, note1 = fofa_search(session, args.key, step1_query, args.size, fields, args.timeout)
    if note1:
        print("  警告: %s" % note1)
    print("  -> %d 条" % len(rows1))
    for row in rows1:
        row["_stage"] = "cert"
    all_rows.extend(rows1)

    main_domains = collect_main_domains(rows1)
    print("Step2 子域名资产（发现主域名 %d 个）" % len(main_domains))
    for domain in main_domains[:5]:
        q = 'domain="%s"' % domain
        rows2, note2 = fofa_search(session, args.key, q, args.size, fields, args.timeout)
        if note2:
            print("  [%s] 警告: %s" % (domain, note2))
        print("  [%s] -> %d 条" % (domain, len(rows2)))
        for row in rows2:
            row["_stage"] = "domain"
        all_rows.extend(rows2)

    # 去重（stage+host+ip+port）
    seen, uniq = set(), []
    for row in all_rows:
        key = (row.get("_stage"), str(row.get("host")), str(row.get("ip")), str(row.get("port")))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(row)

    out_dir = os.path.dirname(os.path.abspath(out_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["stage"] + fields)
        for row in uniq:
            writer.writerow([row.get("_stage", "")] + [row.get(f, "") for f in fields])

    print("Step3/4 汇总: %d 条（去重后）" % len(uniq))
    print("结果已写入: %s" % out_path)
    print("后续动作：证书反查得到的主办单位/域名可继续反查更多资产；新发现资产建议入库（source=supply-chain）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
