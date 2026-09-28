#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""代码 / 仓库泄露搜索工具（被动信息收集）。

用于搜索公开代码平台中与目标相关的泄露：源码、密钥、配置文件、内部域名。

数据源（已按实测可用性排序）：
- github-repo  GitHub Repository Search（默认，免 token 可用）：搜仓库名/描述/README。
                适合发现"与目标同名/相关的可疑仓库"，但要搜外部组织仓库需加 `org:` / `user:` 前缀。
- github-code  GitHub Code Search（需 GITHUB_TOKEN 或 --token）：搜代码内容本身，
                是"源码/密钥泄露"最直接的来源，但 GitHub 已对未认证请求返回 401。
- grep.app     公开代码搜索（无需 token）；但部分数据中心 IP 会被 Vercel 安全挑战拦截（返回 429）。

用法：
  sg_code_search.py -q "example.com password"                          # 默认 github-repo
  sg_code_search.py -q "example.com" --source github-code --token "$GITHUB_TOKEN"
  sg_code_search.py -q "example.com" --source github-repo --pattern "in:readme"
  sg_code_search.py --list keywords.txt -o result.txt
"""

import argparse
import json
import os
import sys
import time

try:
    import requests
except ImportError:  # pragma: no cover
    print("需要 requests：pip install requests", file=sys.stderr)
    sys.exit(2)

GREP_APP_ENDPOINT = "https://grep.app/api/search"
GITHUB_CODE_ENDPOINT = "https://api.github.com/search/code"
GITHUB_REPO_ENDPOINT = "https://api.github.com/search/repositories"
USER_AGENT = "CyberStrikeAI-sg-code-search/1.0"


def load_queries(args):
    queries = []
    if args.query:
        queries.append(args.query.strip())
    if args.list:
        with open(args.list, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                s = line.strip()
                if s and not s.startswith("#"):
                    queries.append(s)
    seen, uniq = set(), []
    for q in queries:
        if q and q not in seen:
            seen.add(q)
            uniq.append(q)
    return uniq


def _squash(text):
    return " ".join(str(text or "").split())[:400]


def search_grep_app(session, query, limit, timeout):
    """grep.app 公开代码搜索。返回 (items, note)。"""
    items = []
    page = 1
    while len(items) < limit and page <= 10:
        try:
            resp = session.get(GREP_APP_ENDPOINT, params={"q": query, "page": page}, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            return items, "request-failed:%s" % type(exc).__name__
        if resp.status_code == 429:
            return items, "blocked:被 Vercel 安全挑战拦截（数据中心 IP 常见），建议改用 github-code 并配置 token"
        if resp.status_code != 200:
            return items, "http-%d" % resp.status_code
        try:
            payload = resp.json()
        except ValueError:
            return items, "bad-json"
        hits = (payload.get("hits") or {}).get("hits") or []
        if not hits:
            break
        for hit in hits:
            repo = ((hit.get("repo") or {}).get("raw")) or ""
            path = ((hit.get("path") or {}).get("raw")) or ""
            branch = ((hit.get("branch") or {}).get("raw")) or ""
            snippet = ((hit.get("content") or {}).get("snippet")) or ""
            if not repo:
                continue
            url = "https://github.com/%s/blob/%s/%s" % (repo, branch or "HEAD", path) if path else "https://github.com/%s" % repo
            items.append({"query": query, "source": "grep.app", "repo": repo,
                          "path": path, "url": url, "snippet": _squash(snippet)})
            if len(items) >= limit:
                break
        page += 1
        time.sleep(0.8)
    return items, ""


def search_github_code(session, query, limit, page_size, timeout):
    """GitHub Code Search（需认证）。返回 (items, note)。"""
    items = []
    headers = {"Accept": "application/vnd.github.text-match+json"}
    per_page = max(1, min(100, page_size))
    page = 1
    while len(items) < limit and page <= 10:
        try:
            resp = session.get(GITHUB_CODE_ENDPOINT,
                               params={"q": query, "per_page": per_page, "page": page},
                               headers=headers, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            return items, "request-failed:%s" % type(exc).__name__
        if resp.status_code == 401:
            return items, "unauthorized:GitHub 代码搜索必须认证，请配置 --token 或 GITHUB_TOKEN"
        if resp.status_code == 403:
            return items, "forbidden:限速或权限不足（未认证为 10 req/min）"
        if resp.status_code == 422:
            return items, "unprocessable:查询语法无效"
        if resp.status_code != 200:
            return items, "http-%d" % resp.status_code
        try:
            payload = resp.json()
        except ValueError:
            return items, "bad-json"
        rows = payload.get("items") or []
        if not rows:
            break
        for row in rows:
            matches = row.get("text_matches") or []
            items.append({
                "query": query,
                "source": "github-code",
                "repo": (row.get("repository") or {}).get("full_name") or "",
                "path": row.get("path") or "",
                "url": row.get("html_url") or "",
                "snippet": _squash(matches[0].get("fragment") if matches else (row.get("description") or "")),
            })
            if len(items) >= limit:
                break
        page += 1
        time.sleep(1.2)
    return items, ""


def search_github_repo(session, query, limit, timeout):
    """GitHub Repository Search（可免认证）。返回 (items, note)。"""
    items = []
    page = 1
    per_page = max(1, min(100, limit))
    while len(items) < limit and page <= 5:
        try:
            resp = session.get(GITHUB_REPO_ENDPOINT,
                               params={"q": query, "per_page": per_page, "page": page},
                               timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            return items, "request-failed:%s" % type(exc).__name__
        if resp.status_code == 403:
            return items, "forbidden:限速（未认证约 10 req/min），可配置 --token 提升"
        if resp.status_code != 200:
            return items, "http-%d" % resp.status_code
        try:
            payload = resp.json()
        except ValueError:
            return items, "bad-json"
        rows = payload.get("items") or []
        if not rows:
            break
        for row in rows:
            items.append({
                "query": query,
                "source": "github-repo",
                "repo": row.get("full_name") or "",
                "path": "",
                "url": row.get("html_url") or "",
                "snippet": _squash(row.get("description") or ""),
            })
            if len(items) >= limit:
                break
        page += 1
        time.sleep(1.0)
    return items, ""


def main():
    parser = argparse.ArgumentParser(description="代码/仓库泄露搜索（被动信息收集）")
    parser.add_argument("-q", "--query", help="搜索关键词")
    parser.add_argument("--list", help="批量关键词文件（每行一个）")
    parser.add_argument("--pattern", default="", help="追加到查询的过滤条件（如 in:readme、org:xxx、fork:yes）")
    parser.add_argument("-o", "--output", help="结果落地文件（默认打印到 stdout）")
    parser.add_argument("-n", "--limit", type=int, default=30, help="每个关键词最多返回条数（默认 30）")
    parser.add_argument("--source", default="github-repo",
                        choices=["github-repo", "github-code", "grep.app"],
                        help="数据源（默认 github-repo，免 token 可用）")
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""),
                        help="GitHub token（也可用 GITHUB_TOKEN 环境变量；github-code 必需）")
    parser.add_argument("--timeout", type=float, default=25.0, help="单次请求超时秒数（默认 25）")
    args = parser.parse_args()

    queries = load_queries(args)
    if not queries:
        print("错误：未提供关键词（--query 或 --list）", file=sys.stderr)
        return 2
    if args.source == "github-code" and not args.token:
        print("警告：github-code 需要认证，未提供 token 时 GitHub 会返回 401。"
              "请用 --token 或设置 GITHUB_TOKEN；或改用 --source github-repo。", file=sys.stderr)

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    if args.token:
        session.headers.update({"Authorization": "Bearer %s" % args.token})

    all_items = []
    for query in queries:
        effective = ("%s %s" % (query, args.pattern)).strip() if args.pattern else query
        note = ""
        if args.source == "github-code":
            items, note = search_github_code(session, effective, args.limit, 30, args.timeout)
        elif args.source == "github-repo":
            items, note = search_github_repo(session, effective, args.limit, args.timeout)
        else:
            items, note = search_grep_app(session, query, args.limit, args.timeout)
        all_items.extend(items)
        line = "[%s] %s -> %d 条" % (args.source, effective, len(items))
        if note:
            line += "（%s）" % note
        print(line)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            for it in all_items:
                fh.write("repo=%s path=%s\n  url=%s\n  snippet=%s\n" % (it["repo"], it["path"], it["url"], it["snippet"]))
        print("结果已写入: %s" % args.output)
    else:
        print("-" * 60)
        for it in all_items:
            print("repo=%s\n  path=%s\n  url=%s\n  snippet=%s" % (it["repo"], it["path"], it["url"], it["snippet"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
