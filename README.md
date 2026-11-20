# 出站探测 API（Egress Probe）

运维人员在启用外部回调（webhook）前，需要确认回调地址**可达**且**不会访问禁区**。
本服务提供一个 FastAPI 出站探测接口：提交 HTTP/HTTPS URL，返回**逐跳状态、DNS 解析
地址、实际连接地址与拒绝原因**，用于调整出口白名单。

## 安全模型（核心保证）

每一跳都完整执行下列流程，跳转目标也不例外：

```
URL 静态校验（不产生流量）
   └─ DNS A 记录查询（只问配置的解析器，绝不用系统 getaddrinfo）
        └─ 全部解析地址逐个过 IPv4 CIDR 白名单
             └─ 全部获准才连接；任一地址在禁区 → 整体拒绝（不返回部分结果）
                  └─ 仅向“检查时已批准的 IP”建 TCP，运行时不再解析 DNS
                       └─ HTTPS 用原域名做 SNI 并验证证书（不可关闭校验）
                            └─ 发送一次请求、读取响应
                                 └─ 3xx 跳转：对 Location 重复整套流程（最多 3 次）
```

由此满足：

| 要求 | 实现方式 |
| --- | --- |
| 仅支持 IPv4 | IPv6 字面量、IPv6 CIDR、AAAA 均拒绝；策略层只接受 `IPv4Address` |
| 启动时配置允许的 CIDR | 环境变量 `ALLOWED_CIDRS`（逗号分隔），非法配置直接拒绝启动 |
| 每跳全部解析地址均获准才连接 | `AddressPolicy.check_resolved` 对完整 A 记录列表做“全或无”判定 |
| 最多跟随 3 次跳转 | `MAX_REDIRECTS=3`（硬上限，启动配置仅允许 0..3） |
| DNS 检查后变化不能进入禁区 | 连接目标固定为校验通过的 IP 字面量，连接阶段不触发任何 DNS |
| 连接重试不能进入禁区 | 重试只在**已批准**的地址集合内逐个尝试，绝不重新解析 |
| 跳转不能进入禁区 | 每个跳转目标重新走“解析→全量校验→连接”，被拒即停 |
| 被拒目标收不到探测请求 | 拒绝发生在任何 socket 创建之前；集成测试与目标访问日志双向验证 |
| HTTPS 按原域名验证证书 | `check_hostname=True`、`CERT_REQUIRED`，SNI/校验均用原域名，无关闭开关 |
| 慢探测不阻塞其他请求 | 全异步 + 单事件循环；并发信号量，满额立即返回 429；单请求总超时 |

## 目录结构

```
app/
  probe/            探测服务
    policy.py       IPv4 CIDR 白名单与 URL 静态校验（所有连接决策的唯一入口）
    planner.py      白名单迁移规划（纯计算：精确最小 CIDR、组合最优选择）
    dns_wire.py     自研 DNS 线协议（RFC1035 子集，查询/应答/压缩指针防护）
    dns_client.py   异步 DNS 客户端（仅向配置的解析器发 A 查询）
    connection.py   固定到已批准 IP 的 TCP 连接 + 强制校验的 TLS
    http_probe.py   逐跳 HTTP/1.1 探测引擎、跳转规范化与上限
    config.py       环境变量配置（启动时校验）
    main.py         FastAPI 应用（/api/v1/probe、/docs）
  dns_service/      本地可切换解析的 DNS（UDP/53 + HTTP 控制面 profile 热切换）
  targets/          演示目标（HTTP/8080、HTTPS/8443，含各类跳转与访问记录）
  certinit/         生成演示 CA、服务器证书、合并 CA bundle
dns-profiles/       DNS 场景：allowed / swapped / mixed / loop / planning
compose.yaml        一键启动的完整演示环境
tests/              127 个测试（策略、DNS 协议、TLS、跳转、并发、规划、API 全链路）
scripts/demo.sh     探测演示脚本
scripts/plan-demo.sh 白名单迁移规划演示脚本（只读）
```

## 快速开始

```bash
docker compose up -d --build
# 探测 API（仅绑定本机回环）
open http://127.0.0.1:8000/docs
```

演示环境网络拓扑（全部 IPv4，静态地址）：

| 网络 | 网段 | 用途 |
| --- | --- | --- |
| `net_dns` | 172.31.0.0/24 | 本地 DNS（172.31.0.53），探测服务唯一使用的解析器 |
| `net_allowed` | 172.31.10.0/24 | 允许目标（172.31.10.10）——**白名单唯一放行的网段** |
| `net_denied` | 172.31.20.0/24 | 禁止目标（172.31.20.10） |

目标服务同时监听标准端口 `80/443`（供跳转 URL 直接使用）与演示端口
`8080/8443`，HTTP 与 HTTPS 行为一致；可用环境变量
`TARGET_HTTP_PORTS` / `TARGET_HTTPS_PORTS` 覆盖监听端口。

> probe 容器**同时接入** `net_denied`（路由层可达），但白名单不含该网段。
> 这证明拦截来自应用层白名单策略，而不是网络隔离。

### 一键演示

```bash
./scripts/demo.sh
```

## API

### `POST /api/v1/probe`

请求体：

```json
{ "url": "https://example.com/path", "method": "GET" }
```

响应（关键字段）：

```json
{
  "outcome": "blocked",
  "summary": "第 1 跳被策略拒绝: 解析结果包含未获准网段的地址: 172.31.20.10；...",
  "allowed_cidrs": ["172.31.10.0/24"],
  "dns_server": "172.31.0.53:53",
  "max_redirects": 3,
  "hops": [
    {
      "hop": 1,
      "url": "http://forbidden.demo.test/secret",
      "hostname": "forbidden.demo.test",
      "resolved_addresses": ["172.31.20.10"],
      "approved_addresses": [],
      "connected_peer": null,
      "request_sent": false,
      "outcome": "blocked",
      "reject_reason": "解析结果包含未获准网段的地址: 172.31.20.10；..."
    }
  ]
}
```

每跳字段含义：

- `resolved_addresses`：DNS 实际返回的全部 A 记录；
- `approved_addresses`：通过白名单的地址（被整体拒绝时为空）；
- `connected_peer`：**实际**建立 TCP 连接的 `ip:port`（固定为已批准 IP）；
- `tls`：TLS 版本、套件、证书 subject/SAN（HTTPS 时）；
- `request_sent`：是否真的发出了 HTTP 请求（被策略拒绝时恒为 `false`）；
- `outcome`：`ok` / `redirected` / `blocked` / `error`；
- `reject_reason` / `error`：拒绝或失败的具体原因。

辅助接口：`GET /api/v1/policy`（当前白名单与超时配置）、`GET /healthz`。

### `POST /api/v1/whitelist/plans`（只读规划）

出口设备的 CIDR 条数有限，值班员希望**保留现有放行范围**的同时尽量多迁移
回调域名。本接口提交候选域名及其在探测报告中的**完整 IPv4 地址组**与设备
CIDR 上限，返回可直接替换当前白名单的 CIDR 清单和可迁移域名。

请求体：

```json
{
  "max_cidrs": 2,
  "domains": [
    { "domain": "hooks.allowed.demo.test", "addresses": ["172.31.10.10"] },
    { "domain": "hooks.external.demo.test",
      "addresses": ["203.0.113.20", "203.0.113.21"] }
  ],
  "current_cidrs": ["172.31.10.0/24"]
}
```

- `domains`：1..12 个，每个域名必须给出**全部** IPv4 地址（至少 1 个，空组 422）；
- `max_cidrs`：设备可容纳的 CIDR 总条数，`>= 0`；
- `current_cidrs`：可选；省略时使用本服务配置的 `ALLOWED_CIDRS`（响应中
  `current_cidrs_source` 标明来源）。

响应（关键字段）：

```json
{
  "feasible": true,
  "migration_possible": true,
  "selected_domains": ["hooks.allowed.demo.test", "hooks.external.demo.test"],
  "cidrs": ["172.31.10.0/24", "203.0.113.20/31"],
  "rule_count": 2,
  "max_cidrs": 2,
  "current_exact_cidrs": ["172.31.10.0/24"],
  "current_rule_count": 1,
  "coverage": {
    "exact": true,
    "covers_current_whitelist": true,
    "selected_domains_fully_covered": true,
    "listed_address_count": 258,
    "expected_union_address_count": 258
  },
  "read_only": true,
  "message": "已生成规划：迁移 2 个域名，共需 2 条 CIDR（上限 2）；..."
}
```

语义保证：

| 要求 | 实现方式 |
| --- | --- |
| 精确保留现有放行范围 | 以**当前白名单的最小精确 CIDR 表示**为基础，结果只做并入 |
| 清单覆盖范围恰好是并集 | 只合并重叠/首尾相邻区间，再用对齐分解；不跨越空洞聚合 |
| 每个地址都放行才可入选 | 入选当且仅当其全部地址包含在清单地址集合中 |
| 上限内域名最多 | 枚举全部子集（≤12 个），优先取域名数最大者 |
| 域名数相同取规则更少 | 同层比较 CIDR 条数；仍相同按域名排序取字典序最小，结果确定 |
| 无可行方案明确告知 | `feasible=false`、`cidrs=[]`、`rule_count=null`，原因在 `message` |
| 只读 | 不发起 DNS/HTTP 请求、不修改任何配置；CPU 搜索在线程池执行 |

> “当前白名单本身已超出上限”同样视为**无可行方案**（`feasible=false`）：
> 此时不存在任何既保持放行范围、又满足上限的清单。

限制：候选域名 ≤12 个；单域名地址 ≤256 个，总地址 ≤1024 个（保证精确搜索在
秒级完成）。空地址组、IPv6 地址/CIDR、重复域名、非法 CIDR 均返回 422。

在 `/docs` 中展开 **plan** 分组，右侧 “Try it out” 上方有 3 个可直接运行的
示例：`demo_merged`（并集与 /31 合并）、`demo_tradeoff`（域名数优先）、
`demo_no_solution`（无解）。

## 演示场景与 DNS profile 切换

本地 DNS 的解析数据按 profile 组织，可热切换：

```bash
# 查看当前 profile 与全部解析数据
curl http://127.0.0.1:8053/profiles
# 切换
curl -X POST http://127.0.0.1:8053/profiles/switch \
  -H 'Content-Type: application/json' -d '{"profile":"swapped"}'
```

| profile | 演示点 |
| --- | --- |
| `allowed` | 正常解析到允许网段 |
| `swapped` | 同名域名从允许地址换到禁止地址（**检查后换址 / DNS rebinding**） |
| `mixed` | 一次应答同时含允许与禁止地址，验证“全部获准才连接” |
| `loop` | 连环 307 跳转，验证 3 次跳转上限 |
| `planning` | 候选回调域名（白名单内/外/禁区），用于规划演示 |

### 规划演示

```bash
# 方式一：一键在 compose 内跑规划演示（自动先用 /probe 收集地址组）
docker compose --profile demo run --rm plan-demo

# 方式二：宿主机上运行（probe 已 up）
./scripts/plan-demo.sh          # 默认设备上限 4 条
MAX_CIDRS=2 ./scripts/plan-demo.sh
```

脚本先逐域名调 `/api/v1/probe` 取完整地址组，再提交规划，并演示上限收紧与
无解两种情形；也可直接在 <http://127.0.0.1:8000/docs> 的 plan 分组里操作。

## 配置项（探测服务环境变量）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `ALLOWED_CIDRS` | （必填） | 逗号分隔的 IPv4 CIDR 白名单 |
| `DNS_SERVER` / `DNS_PORT` | 127.0.0.1 / 53 | 唯一允许使用的解析器（IP 字面量） |
| `DNS_TIMEOUT` / `DNS_RETRIES` | 3.0 / 1 | DNS 单次超时与重试次数 |
| `CA_BUNDLE` | 系统信任库 | 信任 CA 文件（演示环境为系统 CA + 演示 CA 合并） |
| `CONNECT_TIMEOUT` / `TLS_TIMEOUT` / `READ_TIMEOUT` | 5 / 8 / 10 秒 | 各阶段超时 |
| `MAX_REDIRECTS` | 3 | 跳转上限，仅允许 0..3 |
| `MAX_CONCURRENCY` | 64 | 在飞探测并发上限，超出返回 429 |
| `PROBE_OVERALL_TIMEOUT` | 30 | 单请求总超时，超时返回 408 |

## 测试

```bash
pip install -r requirements.txt pytest pytest-asyncio httpx
pytest -q
```

127 个测试覆盖：CIDR/URL 策略、DNS 编解码与压缩指针环路、全链路探测、
混合解析整体拒绝、检查后换址、跳转上限/跳禁区/非 HTTP 协议、HTTPS 证书
主机名校验与不受信证书拒绝、慢探测并发非阻塞、429 保护、API 层，以及
白名单规划（精确最小 CIDR、覆盖核对、域名数/规则数最优、无解与只读）。

## 设计边界与说明

- 探测只实现 GET/HEAD、HTTP/1.1，读取响应体有 64KB 上限，仅用于连通性判断；
- 不跟随 cookie、不发送请求体、不执行任何页面脚本；
- DNS 仅做 A 记录查询（AAAA 不存在即天然 IPv4-only）；
- 演示 CA 与证书仅用于本地/compose 演示，生产环境应使用真实 PKI 并通过
  `CA_BUNDLE` 指定信任根。
- 规划 API 是**无状态纯计算**：结果不会被下发到设备，也不会改写
  `ALLOWED_CIDRS`；需要值班员自行审核后替换。清单基于请求方提交的地址组，
  地址组必须来自探测报告的完整 `resolved_addresses`。
