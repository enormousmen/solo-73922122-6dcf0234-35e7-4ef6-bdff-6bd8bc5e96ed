#!/usr/bin/env bash
# 白名单迁移规划 API 演示（只读；配合 compose 环境运行）。
#
# 用法：
#   docker compose up -d --build
#   ./scripts/plan-demo.sh
#
# 覆盖三个场景：
#   1) 从探测报告收集各候选域名的完整 IPv4 地址组，提交规划并保存清单；
#   2) 上限收紧后的取舍（域名数优先，其次规则更少）；
#   3) 无可行方案（现有白名单本身已超出设备上限）时明确告知。
#
# 交互式文档：http://127.0.0.1:8000/docs  →  “plan” 分组 → Try it out
set -euo pipefail

BASE="${PROBE_BASE:-http://127.0.0.1:8000}"
DNS_CTRL="${DNS_CTRL:-http://127.0.0.1:8053}"
MAX_CIDRS="${MAX_CIDRS:-4}"

require() { command -v "$1" >/dev/null || { echo "缺少依赖: $1" >&2; exit 1; }; }
require curl
require jq

echo "### 0. 当前白名单（规划默认以此为准）"
POLICY="$(curl -sS "${BASE}/api/v1/policy")"
echo "${POLICY}" | jq '{allowed_cidrs, max_redirects}'
CURRENT_CIDRS="$(echo "${POLICY}" | jq -c '.allowed_cidrs')"

echo
echo "--- 切换演示 DNS profile -> planning"
curl -sS -X POST "${DNS_CTRL}/profiles/switch" \
  -H 'Content-Type: application/json' -d '{"profile":"planning"}' \
  | jq -r '.active'

# 候选域名：前三个已在白名单网段内（零新增规则），其余在外部或禁区。
CANDIDATES=(
  hooks.inside.demo.test
  hooks.inside2.demo.test
  hooks.webhook.demo.test
  hooks.external.demo.test
  hooks.external2.demo.test
  hooks.multi-a.demo.test
  hooks.denied.demo.test
)

echo
echo "### 1. 逐个探测候选域名，取探测报告中的完整 IPv4 地址组"
DOMAINS_JSON='[]'
for domain in "${CANDIDATES[@]}"; do
  HOP="$(curl -sS -X POST "${BASE}/api/v1/probe" \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg u "http://${domain}/" '{url:$u, method:"GET"}')" \
    | jq '.hops[0]')"
  IPS="$(echo "${HOP}" | jq -c '.resolved_addresses // []')"
  echo "  ${domain}: outcome=$(echo "${HOP}" | jq -r '.outcome')" \
       "resolved=${IPS}"
  if [ "$(echo "${IPS}" | jq 'length')" -eq 0 ]; then
    echo "    ↳ 跳过：探测报告没有 IPv4 地址（DNS 失败或 NXDOMAIN），无法确认放行范围"
    continue
  fi
  DOMAINS_JSON="$(jq -n --argjson acc "${DOMAINS_JSON}" --arg d "${domain}" \
    --argjson ips "${IPS}" '$acc + [{domain:$d, addresses:$ips}]')"
done

echo
echo "### 2. 提交规划（设备上限 ${MAX_CIDRS} 条 CIDR）"
BODY="$(jq -n \
  --argjson current "${CURRENT_CIDRS}" \
  --argjson domains "${DOMAINS_JSON}" \
  --argjson cap "${MAX_CIDRS}" \
  '{current_cidrs:$current, domains:$domains, max_cidrs:$cap}')"
RESULT="$(curl -sS -X POST "${BASE}/api/v1/whitelist/plans" \
  -H 'Content-Type: application/json' -d "${BODY}")"
echo "${RESULT}" | jq '{
  feasible, migration_possible, message,
  selected_domains, cidrs, rule_count, max_cidrs,
  current_exact_cidrs, current_rule_count,
  coverage,
  candidates: [.candidates[] | {domain, selected, reason}]
}'
echo
echo "可直接替换当前白名单的 CIDR 清单："
echo "${RESULT}" | jq -r '.cidrs[] | "  " + .'

echo
echo "### 3. 收紧上限后的取舍（域名数 > 规则数）"
curl -sS -X POST "${BASE}/api/v1/whitelist/plans" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n \
        --argjson current "${CURRENT_CIDRS}" \
        --argjson domains "${DOMAINS_JSON}" \
        '{current_cidrs:$current, domains:$domains, max_cidrs:1}')" \
  | jq '{feasible, migration_possible, message, selected_domains, cidrs, rule_count}'

echo
echo "### 4. 无可行方案（现有白名单最小精确表示已超过上限）"
curl -sS -X POST "${BASE}/api/v1/whitelist/plans" \
  -H 'Content-Type: application/json' \
  -d '{
        "current_cidrs": ["172.31.10.0/24", "172.31.20.0/24"],
        "max_cidrs": 1,
        "domains": [
          {"domain": "hooks.external.demo.test", "addresses": ["203.0.113.20"]}
        ]
      }' \
  | jq '{feasible, migration_possible, message, cidrs, rule_count, coverage}'

echo
echo "演示完成。交互式规划文档: ${BASE}/docs （plan 分组，含 3 个可直接运行的示例）"
