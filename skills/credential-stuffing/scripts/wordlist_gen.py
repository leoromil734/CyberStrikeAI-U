#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""针对性弱口令字典生成器（离线、确定性、纯标准库）。

根据已掌握的情报（品牌名、人名、邮箱前缀、域名、产品词、年份）生成一份
小型高概率候选字典，供 credential-stuffing 技能在预算内使用。输出按优先级
排序：先用最可能命中的候选，预算用尽即停。

用法示例：
  python3 wordlist_gen.py \
    --base libertysilver --base "liberty silver" \
    --name "Caroline Eking" --email-prefix caroline.eking \
    --domain libertysilver.se --product myaccount \
    --year-from 2023 --year-to 2026 --max 800 --out wordlist.txt

约束：
- 不联网、不读外部字典（内置通用弱口令小表可选）；
- 同参数输出完全一致（便于记录 hash 与复现）；
- 仅生成候选，不执行任何认证请求。
"""

import argparse
import hashlib
import itertools
import sys
from datetime import datetime

# 通用弱口令小表（仅在 --include-common 时追加到末尾，按优先级排序）
COMMON_PASSWORDS = [
    "password", "Password", "Password1", "Password1!", "Passw0rd", "P@ssw0rd",
    "123456", "12345678", "123456789", "1234567890", "12345", "1234", "111111",
    "qwerty", "Qwerty123", "qwerty123", "1qaz2wsx", "zaq12wsx", "qazwsx",
    "asdfgh", "admin", "admin123", "Admin123", "administrator", "root",
    "welcome", "Welcome1", "Welcome1!", "letmein", "charlie", "monkey",
    "dragon", "master", "sunshine", "princess", "football", "iloveyou",
    "abc123", "abcd1234", "a1b2c3", "1q2w3e4r", "Aa123456", "Aa123456!",
    "test123", "guest", "changeme", "secret", "vpn123", "webmail", "mail123",
]

# 常见数字/符号后缀（按命中概率排序）
NUM_SUFFIXES = ["1", "12", "123", "1234", "12345", "123456",
                "01", "001", "007", "321", "666", "888", "99", "00"]
SYM_SUFFIXES = ["!", "!!", "!!!", "@", "#", ".", "?", "*", "!@#", "@123", "!23"]
LEET_MAP = [
    ("a", "@"), ("a", "4"), ("e", "3"), ("i", "1"), ("o", "0"),
    ("s", "$"), ("s", "5"), ("t", "7"), ("g", "9"), ("b", "8"),
]
KEYBOARD_PATTERNS = [
    "qwerty", "qwerty123", "qwerty1", "qwerty!", "1qaz2wsx", "1qaz2wsx3edc",
    "zaq12wsx", "qazwsx", "qazwsx123", "asdfgh", "asdfghjkl", "qwe123",
    "1q2w3e", "1q2w3e4r", "1q2w3e4r5t", "qaz123", "wsx123", "qweasd",
]


def slug_variants(word):
    """基词的常见书写变体：原样、首字母大写、短词全大写、去分隔符。"""
    out = []
    w = word.strip()
    if not w:
        return out
    seen = set()

    def add(value):
        if value and value not in seen:
            seen.add(value)
            out.append(value)

    add(w)
    add(w.capitalize())
    add(w.lower())
    if len(w) <= 8 and " " not in w and "-" not in w:
        add(w.upper())
    # 分隔符变体：liberty silver / liberty-silver / libertysilver
    compact = w.replace(" ", "").replace("-", "").replace("_", "")
    add(compact)
    add(compact.capitalize())
    if " " in w:
        add(w.replace(" ", "-"))
        add(w.replace(" ", "_"))
    if "-" in w:
        add(w.replace("-", ""))
        add(w.replace("-", " "))
    return out


def name_tokens(full_name):
    """人名 → first / last / 全名 / 缩写组合。"""
    parts = [p for p in full_name.replace("-", " ").split() if p]
    out = []
    if not parts:
        return out
    out.append("".join(parts))                      # carolineeking
    out.append(parts[0])                            # caroline
    out.append(parts[0].capitalize())
    if len(parts) > 1:
        out.append(parts[-1])                       # eking
        out.append(parts[-1].capitalize())
        out.append(parts[0] + "." + parts[-1])      # caroline.eking
        out.append(parts[-1] + parts[0])            # ekingcaroline
        out.append(parts[0][0] + parts[-1])         # ceking
        out.append(parts[0] + parts[-1])            # carolineeking
    return out


def email_prefix_variants(prefix):
    """邮箱前缀 → 原样与片段（caroline.eking → caroline.eking/caroline/eking/ceking）。"""
    p = prefix.strip()
    out = []
    if not p:
        return out
    out.append(p)
    out.append(p.split("@")[0])
    base = p.split("@")[0]
    for sep in (".", "_", "-"):
        if sep in base:
            chunks = [c for c in base.split(sep) if c]
            out.extend(chunks)
            if len(chunks) > 1:
                out.append("".join(chunks))
                out.append(chunks[0][0] + chunks[-1])
    return out


def domain_label(domain):
    """域名 → 主标签（libertysilver.se → libertysilver）。"""
    d = domain.strip().lower().strip(".")
    if not d:
        return ""
    parts = d.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


def leet_variants(word, limit=6):
    """对短词做有限的 l33t 替换组合。"""
    out = []
    w = word.lower()
    if not (3 <= len(w) <= 12):
        return out
    for src, dst in LEET_MAP:
        if src in w:
            # 只替换第一处，避免指数爆炸
            idx = w.find(src)
            cand = w[:idx] + dst + w[idx + 1:]
            if cand != w and cand not in out:
                out.append(cand)
        if len(out) >= limit:
            break
    return out


def build_candidates(args):
    years = list(range(args.year_from, args.year_to + 1))
    short_years = sorted({str(y)[2:] for y in years})

    bases = []
    for b in args.base:
        bases.extend(slug_variants(b))
    for e in args.extra:
        bases.extend(slug_variants(e))

    names = []
    for n in args.name:
        names.extend(name_tokens(n))

    prefixes = []
    for p in args.email_prefix:
        prefixes.extend(email_prefix_variants(p))

    products = []
    for p in args.product:
        products.extend(slug_variants(p))

    domains = [domain_label(d) for d in args.domain]
    domains = [d for d in domains if d]
    for d in domains:
        bases.extend(slug_variants(d))

    # 去重且保序的基词池：品牌/域名在前，人名其后，产品词最后
    primary, seen = [], set()
    for w in bases + names + prefixes + products:
        if w and w not in seen:
            seen.add(w)
            primary.append(w)

    out = []

    def add(value):
        if value and value not in seen_values:
            seen_values.add(value)
            out.append(value)

    seen_values = set()

    # P0：基词原样
    for w in primary:
        add(w)

    # P1：基词 + 数字/符号/短年份后缀
    for w in primary:
        for s in NUM_SUFFIXES[:8]:
            add(w + s)
        for s in SYM_SUFFIXES[:6]:
            add(w + s)
        for y in short_years:
            add(w + y)
        for y in years:
            add(w + str(y))

    # P2：基词 + 年份 + 符号 / 符号 + 年份
    for w in primary:
        for y in years:
            add(f"{w}{y}!")
            add(f"{w}@{y}")
            add(f"{w}{y}@")
            add(f"{w}#{y}")
    for w in primary:
        for y in short_years[:4]:
            add(f"{w}{y}!")

    # P3：双词组合（品牌×人名等，抽样优先组合）
    if len(primary) > 1:
        for a, b in itertools.islice(itertools.permutations(primary[:10], 2), 60):
            add(a + b)
            add(a.capitalize() + b.capitalize())

    # P4：l33t 变体
    if args.leet:
        for w in primary[:40]:
            for v in leet_variants(w):
                add(v)
                add(v.capitalize())

    # P5：键盘模式
    for w in KEYBOARD_PATTERNS:
        add(w)

    # P6：通用弱口令补充（可关闭）
    if args.include_common:
        for w in COMMON_PASSWORDS:
            add(w)

    if args.max > 0:
        out = out[: args.max]
    return out


def main():
    parser = argparse.ArgumentParser(
        description="根据已知信息（品牌/人名/邮箱前缀/域名/年份）生成针对性弱口令候选字典",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--base", action="append", default=[], help="品牌/组织名（可多次）")
    parser.add_argument("--extra", action="append", default=[], help="任意附加基词（可多次）")
    parser.add_argument("--name", action="append", default=[], help="人名，如 'Caroline Eking'（可多次）")
    parser.add_argument("--email-prefix", action="append", default=[], help="邮箱前缀，如 caroline.eking（可多次）")
    parser.add_argument("--domain", action="append", default=[], help="域名，如 libertysilver.se（可多次）")
    parser.add_argument("--product", action="append", default=[], help="产品/路径词，如 myaccount（可多次）")
    now_year = datetime.now().year
    parser.add_argument("--year-from", type=int, default=now_year - 3, help="年份范围起点")
    parser.add_argument("--year-to", type=int, default=now_year + 1, help="年份范围终点")
    parser.add_argument("--max", type=int, default=1200, help="输出上限（<=0 表示不限制）")
    parser.add_argument("--include-common", dest="include_common", action="store_true",
                        default=True, help="末尾追加通用弱口令小表（默认开启）")
    parser.add_argument("--no-common", dest="include_common", action="store_false",
                        help="不追加通用弱口令小表")
    parser.add_argument("--leet", dest="leet", action="store_true", default=True,
                        help="生成 l33t 变体（默认开启）")
    parser.add_argument("--no-leet", dest="leet", action="store_false", help="不生成 l33t 变体")
    parser.add_argument("--stdin", action="store_true", help="从标准输入按行读取附加基词")
    parser.add_argument("--out", default="", help="输出文件；缺省写标准输出")
    parser.add_argument("--quiet", action="store_true", help="仅输出统计信息")
    args = parser.parse_args()

    if args.stdin:
        for line in sys.stdin:
            word = line.strip()
            if word:
                args.extra.append(word)

    if not any([args.base, args.extra, args.name, args.email_prefix, args.domain, args.product]):
        parser.error("至少提供 --base/--name/--email-prefix/--domain/--product/--extra 之一")

    words = build_candidates(args)

    data = "\n".join(words) + ("\n" if words else "")
    digest = hashlib.sha256(data.encode("utf-8")).hexdigest()
    stats = f"lines={len(words)} bytes={len(data.encode('utf-8'))} sha256={digest}"

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(data)
        print(f"wordlist written: {args.out} {stats}", file=sys.stderr)
    elif args.quiet:
        print(stats, file=sys.stderr)
    else:
        sys.stdout.write(data)
        print(stats, file=sys.stderr)


if __name__ == "__main__":
    main()
