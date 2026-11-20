"""出口白名单迁移规划（纯计算，只读，不发起任何网络请求）。

问题定义
--------
已有白名单 ``C``（若干 IPv4 CIDR），候选域名及其探测得到的完整 IPv4 地址组
``A_i``。选择域名子集 ``T``，令目标放行集合为::

    S = C ∪ ⋃(A_i for i in T)

返回的 CIDR 清单必须 **精确覆盖** ``S``（不多放行任何地址，也不少放行），且
条数不超过设备上限。目标：

1. 最大化 ``|T|``（迁移域名数最多）；
2. 域名数相同时最小化 CIDR 条数；
3. 仍相同时按域名排列取字典序最小者，保证结果确定。

关键点：``S`` 的“精确且最少条数”的 CIDR 表示是唯一的——先把所有地址区间
排序、合并重叠/相邻区间，再用 RFC 4632 的区间分解得到对齐的 CIDR。任何跨越
空洞的聚合都会多放行地址，因而不允许。

本模块不读取 DNS、不修改配置，API 层只把当前白名单与请求体传进来。
"""

from __future__ import annotations

import heapq
import ipaddress
import re
from dataclasses import dataclass
from itertools import combinations
from typing import Iterable, Sequence

IPv4Address = ipaddress.IPv4Address
IPv4Network = ipaddress.IPv4Network

MAX_CANDIDATE_DOMAINS = 12
MAX_ADDRESSES_PER_DOMAIN = 256
# 组合枚举为精确最优搜索；限制总地址数把最坏耗时控制在秒级（实测 < 6s），
# 且 API 层在线程池中执行，不会阻塞探测事件循环。
MAX_TOTAL_ADDRESSES = 1024
_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")


class PlanError(ValueError):
    """规划输入非法。API 层会将其转换为 422 响应。"""


@dataclass(frozen=True)
class CandidateResult:
    """单个候选域名的规划结论。"""

    domain: str
    addresses: tuple[str, ...]
    selected: bool
    reason: str


@dataclass(frozen=True)
class PlanResult:
    """规划结果（不可变，便于测试与 API 序列化）。"""

    feasible: bool
    migration_possible: bool
    selected_domains: tuple[str, ...]
    cidrs: tuple[IPv4Network, ...]
    rule_count: int | None
    max_cidrs: int
    current_configured_cidrs: tuple[IPv4Network, ...]
    current_exact_cidrs: tuple[IPv4Network, ...]
    current_rule_count: int
    candidates: tuple[CandidateResult, ...]
    coverage: CoverageCheck
    message: str


def parse_ipv4_address(raw: str) -> IPv4Address:
    """解析单个 IPv4 地址；IPv6、非法值一律拒绝。"""
    text = str(raw).strip()
    try:
        addr = ipaddress.ip_address(text)
    except ValueError as exc:
        raise PlanError(f"非法 IP 地址: {raw!r}") from exc
    if addr.version != 4:
        raise PlanError(f"仅支持 IPv4 地址，拒绝 IPv6: {raw!r}")
    return IPv4Address(addr)


def parse_ipv4_network(raw: str) -> IPv4Network:
    """解析单个 IPv4 CIDR（strict，主机位必须为 0）。"""
    text = str(raw).strip()
    try:
        net = ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        raise PlanError(f"非法 CIDR: {raw!r} ({exc})") from exc
    if net.version != 4:
        raise PlanError(f"仅支持 IPv4 CIDR，拒绝 IPv6: {raw!r}")
    return IPv4Network(net)


def normalize_domain(raw: str) -> str:
    """域名规范化：去空白、去尾部根点、转小写，并校验主机名形状。

    允许普通 DNS 名称（含下划线）、单标签名与 ``*.`` 通配前缀；不允许空白、
    空标签、超长标签或非 ASCII 字符（调用方应先转成 punycode）。
    """
    if not isinstance(raw, str):
        raise PlanError("域名必须是字符串")
    domain = raw.strip().rstrip(".").lower()
    if not domain:
        raise PlanError("域名不能为空")
    if len(domain) > 253:
        raise PlanError("域名过长（上限 253 字符）")
    if any(ch.isspace() for ch in domain):
        raise PlanError(f"域名中不能包含空白: {raw!r}")
    labels = domain.split(".")
    if labels and labels[0] == "*":
        labels = labels[1:]
    if not labels:
        raise PlanError(f"域名非法: {raw!r}")
    for label in labels:
        if not label or len(label) > 63 or not _LABEL_RE.match(label):
            raise PlanError(f"域名非法: {raw!r}")
    return domain


def _merge_intervals(networks: Iterable[IPv4Network]) -> list[tuple[int, int]]:
    """把网段合并为连续地址区间（仅合并重叠或首尾相邻，绝不跨越空洞）。"""
    return _merge_int_intervals(
        (int(net.network_address), int(net.broadcast_address)) for net in networks
    )


def _merge_int_intervals(
    intervals: Iterable[tuple[int, int]]
) -> list[tuple[int, int]]:
    """合并整数地址区间；只合并重叠/首尾相邻，绝不跨越空洞。"""
    merged: list[list[int]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1] + 1:
            if end > merged[-1][1]:
                merged[-1][1] = end
        else:
            merged.append([start, end])
    return [(start, end) for start, end in merged]


def _count_cidrs_in_run(start: int, end: int) -> int:
    """单个连续地址区间 [start, end] 的最少精确 CIDR 条数（纯位运算）。"""
    count = 0
    while start <= end:
        # 从 start 开始能对齐的最大块：start 的最低位决定对齐粒度
        block = (start & -start) if start else 1 << 32
        remaining = end - start + 1
        while block > remaining:
            block >>= 1
        start += block
        count += 1
    return count


def _bounded_rule_count(
    sorted_lists: Sequence[Sequence[tuple[int, int]]], limit: int
) -> int | None:
    """多路合并若干有序区间列表，返回精确 CIDR 条数；超过 limit 立即返回 None。

    搜索热路径：按区间流式合并，一旦条数超过上限就停止，避免完整排序与构造。
    """
    total = 0
    run_start: int | None = None
    run_end = 0
    for start, end in heapq.merge(*sorted_lists):
        if run_start is None:
            run_start, run_end = start, end
        elif start <= run_end + 1:
            if end > run_end:
                run_end = end
        else:
            total += _count_cidrs_in_run(run_start, run_end)
            if total > limit:
                return None
            run_start, run_end = start, end
    if run_start is not None:
        total += _count_cidrs_in_run(run_start, run_end)
    return total if total <= limit else None


def _address_networks(addresses: Sequence[IPv4Address]) -> tuple[IPv4Network, ...]:
    return tuple(IPv4Network(f"{addr}/32") for addr in addresses)


def minimal_exact_cidrs(networks: Iterable[IPv4Network]) -> tuple[IPv4Network, ...]:
    """返回精确覆盖给定 IPv4 网段并集、且条数最少的 CIDR 列表。

    * 先合并重叠或首尾相邻的地址区间（合并后仍是原集合，不会扩大范围）；
    * 每个连续区间用 ``summarize_address_range`` 做对齐分解，结果最少且精确；
    * 不同区间之间的空洞不会被跨越，因此不会多放行任何地址。
    """
    nets = tuple(networks)
    for net in nets:
        if net.version != 4:
            raise PlanError(f"仅支持 IPv4 CIDR: {net}")
    result: list[IPv4Network] = []
    for start, end in _merge_intervals(nets):
        result.extend(
            IPv4Network(net)
            for net in ipaddress.summarize_address_range(
                IPv4Address(start), IPv4Address(end)
            )
        )
    return tuple(result)


@dataclass(frozen=True)
class CoverageCheck:
    """对规划清单的独立核对结果（供 API 展示，亦用于测试）。"""

    exact: bool
    covers_current_whitelist: bool
    selected_domains_fully_covered: bool
    listed_address_count: int
    expected_union_address_count: int


def check_coverage(
    current_nets: Sequence[IPv4Network],
    selected_addresses: Sequence[IPv4Address],
    cidrs: Sequence[IPv4Network],
) -> CoverageCheck:
    """核对 ``cidrs`` 的覆盖范围是否恰好等于“当前白名单 ∪ 入选域名地址”。

    三条同时成立才算 ``exact``：

    1. 当前白名单的每个地址都出现在清单中；
    2. 入选域名的每个地址都出现在清单中；
    3. 清单地址总数等于并集地址总数（不存在多放行的地址）。
    """
    listed = _merge_intervals(cidrs)
    expected_sources = list(current_nets) + [
        IPv4Network(f"{addr}/32") for addr in selected_addresses
    ]
    expected = _merge_intervals(expected_sources)

    def _contained(start: int, end: int) -> bool:
        return any(lo <= start and end <= hi for lo, hi in listed)

    covers_current = all(
        _contained(int(net.network_address), int(net.broadcast_address))
        for net in current_nets
    )
    covers_selected = all(
        _contained(int(addr), int(addr)) for addr in selected_addresses
    )
    listed_count = sum(hi - lo + 1 for lo, hi in listed)
    expected_count = sum(hi - lo + 1 for lo, hi in expected)
    return CoverageCheck(
        exact=(
            covers_current
            and covers_selected
            and listed_count == expected_count
        ),
        covers_current_whitelist=covers_current,
        selected_domains_fully_covered=covers_selected,
        listed_address_count=listed_count,
        expected_union_address_count=expected_count,
    )


def build_plan(
    current_cidrs: Sequence[str | IPv4Network],
    domains: Sequence[tuple[str, Sequence[str | IPv4Address]]],
    max_cidrs: int,
) -> PlanResult:
    """计算最大化迁移域名数的白名单 CIDR 规划。

    ``domains`` 中每个元素是 ``(域名, 完整 IPv4 地址组)``。地址组为空的域名
    无法证明“全部地址都已放行”，不会被选中；同一域名重复提交直接拒绝。
    候选域名最多 12 个（API 层限制），内部也做防御性校验。
    """
    if max_cidrs < 0:
        raise PlanError("设备可容纳的 CIDR 条数不能为负")
    if len(domains) > MAX_CANDIDATE_DOMAINS:
        raise PlanError(
            f"候选域名最多 {MAX_CANDIDATE_DOMAINS} 个，实际 {len(domains)} 个"
        )

    current_nets = tuple(
        net if isinstance(net, IPv4Network) else parse_ipv4_network(str(net))
        for net in current_cidrs
    )
    current_exact = minimal_exact_cidrs(current_nets)

    parsed: list[tuple[str, tuple[IPv4Address, ...]]] = []
    seen_domains: set[str] = set()
    total_addresses = 0
    for raw_domain, raw_addresses in domains:
        domain = normalize_domain(raw_domain)
        if domain in seen_domains:
            raise PlanError(f"候选域名重复: {domain}")
        seen_domains.add(domain)
        if len(raw_addresses) > MAX_ADDRESSES_PER_DOMAIN:
            raise PlanError(
                f"域名 {domain} 的地址组超过 {MAX_ADDRESSES_PER_DOMAIN} 个"
            )
        seen_ips: set[IPv4Address] = set()
        addresses: list[IPv4Address] = []
        for raw_ip in raw_addresses:
            ip = (
                raw_ip
                if isinstance(raw_ip, IPv4Address)
                else parse_ipv4_address(str(raw_ip))
            )
            if ip not in seen_ips:
                seen_ips.add(ip)
                addresses.append(ip)
        if not addresses:
            raise PlanError(
                f"域名 {domain} 的地址组为空：探测报告没有 IPv4 地址，"
                "无法确认全部地址已放行，不能参与规划"
            )
        total_addresses += len(addresses)
        if total_addresses > MAX_TOTAL_ADDRESSES:
            raise PlanError(f"地址总数超过 {MAX_TOTAL_ADDRESSES} 个")
        parsed.append((domain, tuple(addresses)))

    # 每个候选域名的地址组都非空（空组在上面的校验中已拒绝）。
    selectable = list(range(len(parsed)))

    if len(current_exact) > max_cidrs:
        candidates = tuple(
            CandidateResult(
                domain=domain,
                addresses=tuple(str(ip) for ip in ips),
                selected=False,
                reason="未入选：无可行方案（仅保留当前白名单就已超出 CIDR 上限）",
            )
            for domain, ips in parsed
        )
        return PlanResult(
            feasible=False,
            migration_possible=False,
            selected_domains=(),
            cidrs=(),
            rule_count=None,
            max_cidrs=max_cidrs,
            current_configured_cidrs=current_nets,
            current_exact_cidrs=current_exact,
            current_rule_count=len(current_exact),
            candidates=candidates,
            coverage=check_coverage(current_nets, (), ()),
            message=(
                f"无可行方案：当前白名单的精确覆盖需要 {len(current_exact)} 条 CIDR，"
                f"超过设备上限 {max_cidrs}；无法在保持现有放行范围的前提下生成清单。"
            ),
        )

    best_indices: tuple[int, ...] = ()
    best_cidrs: tuple[IPv4Network, ...] = current_exact
    best_key: tuple[int, int, tuple[str, ...]] = (0, len(current_exact), ())
    base_intervals = _merge_intervals(current_nets)
    # 每个域名的地址区间先排好序，供多路归并流式计数
    domain_intervals = [
        sorted((int(ip), int(ip)) for ip in ips) for _domain, ips in parsed
    ]

    def _candidate_rule_count(combo: tuple[int, ...]) -> int | None:
        """该组合的精确 CIDR 条数；超过上限返回 None（不做完整构造）。"""
        return _bounded_rule_count(
            [base_intervals, *(domain_intervals[idx] for idx in combo)],
            max_cidrs,
        )

    # 域名数优先：从多到少枚举，第一层找到可行解后即可停止。
    # 同一层内选择 (CIDR 条数, 域名排序) 最小者，保证结果确定且与输入顺序无关。
    for size in range(len(selectable), 0, -1):
        found_at_size = False
        for combo in combinations(selectable, size):
            rule_count = _candidate_rule_count(combo)
            if rule_count is None:
                continue
            key = (
                -size,
                rule_count,
                tuple(sorted(parsed[idx][0] for idx in combo)),
            )
            if key < best_key:
                nets = list(current_nets)
                for idx in combo:
                    nets.extend(_address_networks(parsed[idx][1]))
                best_key = key
                best_indices = combo
                best_cidrs = minimal_exact_cidrs(nets)
                found_at_size = True
        if found_at_size:
            break

    selected_set = set(best_indices)
    selected_domains = tuple(parsed[i][0] for i in best_indices)
    rule_count = len(best_cidrs)

    # 为未入选域名给出可核对的理由，便于值班员调整上限或地址。
    candidates = []
    for idx, (domain, ips) in enumerate(parsed):
        if idx in selected_set:
            reason = f"入选：全部 {len(ips)} 个地址均被结果清单覆盖"
            selected = True
        else:
            alone = minimal_exact_cidrs(
                list(current_nets) + list(_address_networks(ips))
            )
            if len(alone) > max_cidrs:
                reason = (
                    f"未入选：单独保留该域名需要 {len(alone)} 条 CIDR，"
                    f"超过上限 {max_cidrs}"
                )
            else:
                reason = (
                    "未入选：在“域名数优先、其次 CIDR 条数更少”的目标下未选中"
                    "（纳入它会减少可迁移域名数或增加清单条数）；"
                    "可提高上限后重新规划"
                )
            selected = False
        candidates.append(
            CandidateResult(
                domain=domain,
                addresses=tuple(str(ip) for ip in ips),
                selected=selected,
                reason=reason,
            )
        )

    if not selected_domains:
        if not parsed:
            message = (
                f"未提交候选域名：清单仅精确覆盖当前白名单，共 {rule_count} 条 CIDR。"
            )
        else:
            message = (
                f"上限内没有可迁移域名：仅保留当前白名单需要 {len(current_exact)} 条 CIDR"
                f"（上限 {max_cidrs}）；加入任一候选域名都会超过上限。"
            )
    else:
        message = (
            f"已生成规划：迁移 {len(selected_domains)} 个域名，共需 {rule_count} 条 CIDR"
            f"（上限 {max_cidrs}）；清单覆盖范围恰好是当前白名单与入选域名全部地址的并集。"
        )

    selected_addresses = tuple(
        ip for idx in best_indices for ip in parsed[idx][1]
    )
    return PlanResult(
        feasible=True,
        migration_possible=bool(selected_domains),
        selected_domains=selected_domains,
        cidrs=best_cidrs,
        rule_count=rule_count,
        max_cidrs=max_cidrs,
        current_configured_cidrs=current_nets,
        current_exact_cidrs=current_exact,
        current_rule_count=len(current_exact),
        candidates=tuple(candidates),
        coverage=check_coverage(current_nets, selected_addresses, best_cidrs),
        message=message,
    )
