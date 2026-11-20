"""白名单迁移规划单元测试（纯计算，无网络）。"""

from __future__ import annotations

import ipaddress

import pytest

from app.probe.planner import (
    PlanError,
    build_plan,
    check_coverage,
    minimal_exact_cidrs,
    normalize_domain,
)

NET = ipaddress.ip_network


def D(domain: str, *addresses: str) -> tuple[str, list[str]]:
    return domain, list(addresses)


def address_set(cidrs) -> set[ipaddress.IPv4Address]:
    """把 CIDR 清单展开为地址集合（仅用于测试中的小范围核对）。"""
    out: set[ipaddress.IPv4Address] = set()
    for raw in cidrs:
        net = NET(str(raw))
        out.update(net)
    return out


class TestMinimalExactCidrs:
    @pytest.mark.parametrize(
        ("nets", "expected"),
        [
            (["10.0.0.0/25", "10.0.0.128/25"], ["10.0.0.0/24"]),
            (["10.0.0.0/24", "10.0.1.0/24"], ["10.0.0.0/23"]),
            (["10.0.0.0/24", "10.1.0.0/24"], ["10.0.0.0/24", "10.1.0.0/24"]),
            (["10.0.0.0/8", "10.1.0.0/16"], ["10.0.0.0/8"]),
            (["10.0.0.5/32", "10.0.0.4/32"], ["10.0.0.4/31"]),
            ([], []),
        ],
    )
    def test_canonical_minimal(self, nets, expected):
        assert [str(n) for n in minimal_exact_cidrs([NET(n) for n in nets])] == (
            expected
        )

    def test_never_merges_across_hole(self):
        # 10.0.0.0/24 与 10.0.2.0/24 之间的 /24 是空洞，聚合会多放行
        result = minimal_exact_cidrs([NET("10.0.0.0/24"), NET("10.0.2.0/24")])
        assert [str(n) for n in result] == ["10.0.0.0/24", "10.0.2.0/24"]

    def test_rejects_ipv6(self):
        with pytest.raises(PlanError, match="IPv4"):
            minimal_exact_cidrs([ipaddress.ip_network("2001:db8::/32")])


class TestCoverageCheck:
    def test_exact(self):
        check = check_coverage(
            [NET("10.0.0.0/24")],
            [ipaddress.ip_address("10.1.0.1")],
            [NET("10.0.0.0/24"), NET("10.1.0.1/32")],
        )
        assert check.exact is True
        assert check.listed_address_count == check.expected_union_address_count == 257

    def test_detects_extra_allowed_address(self):
        # 清单错误地聚合了 10.0.0.0/23（多放行 10.0.1.0/24）
        check = check_coverage(
            [NET("10.0.0.0/24")], [], [NET("10.0.0.0/23")]
        )
        assert check.exact is False
        assert check.listed_address_count > check.expected_union_address_count

    def test_detects_missing_address(self):
        check = check_coverage(
            [NET("10.0.0.0/24")],
            [ipaddress.ip_address("10.1.0.1")],
            [NET("10.0.0.0/24")],
        )
        assert check.exact is False
        assert check.selected_domains_fully_covered is False


class TestNormalizeDomain:
    def test_normalizes_case_and_trailing_dot(self):
        assert normalize_domain(" Hooks.Example.COM. ") == "hooks.example.com"

    @pytest.mark.parametrize("bad", ["", "   ", "a b.test", "."])
    def test_rejects_empty_or_whitespace(self, bad):
        with pytest.raises(PlanError):
            normalize_domain(bad)


class TestBuildPlan:
    def test_all_domains_selected_when_rules_fit(self):
        plan = build_plan(
            ["172.31.10.0/24"],
            [D("a.test", "172.31.10.10"), D("b.test", "172.31.10.20", "172.31.10.21")],
            3,
        )
        assert plan.feasible is True
        assert plan.migration_possible is True
        assert plan.selected_domains == ("a.test", "b.test")
        assert [str(n) for n in plan.cidrs] == ["172.31.10.0/24"]
        assert plan.rule_count == 1
        assert plan.coverage.exact is True

    def test_result_equals_exact_union(self):
        current = ["172.31.10.0/24"]
        domains = [
            D("a", "172.31.10.200"),
            D("b", "203.0.113.7", "203.0.113.8"),
            D("c", "198.51.100.1"),
        ]
        plan = build_plan(current, domains, 10)
        selected_ips = {
            ipaddress.ip_address(ip)
            for d in domains
            if d[0] in plan.selected_domains
            for ip in d[1]
        }
        expected = address_set(current) | selected_ips
        assert address_set(plan.cidrs) == expected
        assert plan.coverage.exact is True

    def test_maximizes_domain_count_first(self):
        # 上限 3：单域名方案可只占 2 条规则，但双域名方案占 3 条，应选双域名
        plan = build_plan(
            ["10.0.0.0/24"],
            [D("solo", "10.5.0.1", "10.7.0.1"), D("x", "10.1.0.1"), D("y", "10.2.0.1")],
            3,
        )
        assert plan.selected_domains == ("x", "y")

    def test_picks_fewer_rules_on_equal_domain_count(self):
        # 同为 1 个域名：aaa 需 2 条新规则（总 3），zzz 只需 1 条（总 2）
        plan = build_plan(
            ["10.0.0.0/24"],
            [D("aaa", "10.5.0.1", "10.7.0.1"), D("zzz", "10.1.0.1")],
            3,
        )
        assert plan.selected_domains == ("zzz",)
        assert plan.rule_count == 2

    def test_lexicographic_tiebreak_deterministic(self):
        domains = [D("b", "10.2.0.1"), D("a", "10.1.0.1")]
        plan1 = build_plan(["10.0.0.0/24"], domains, 2)
        plan2 = build_plan(["10.0.0.0/24"], list(reversed(domains)), 2)
        assert plan1.selected_domains == plan2.selected_domains == ("a",)

    def test_domain_with_partially_allowed_addresses_is_not_counted(self):
        # b 的 10.1.0.1 在清单覆盖之外（无法在 1 条规则内同时放行两处），
        # 但 a 的地址已在白名单内，可零成本迁移
        plan = build_plan(
            ["10.0.0.0/24"],
            [D("a", "10.0.0.50"), D("b", "10.1.0.1")],
            1,
        )
        assert plan.selected_domains == ("a",)
        assert plan.cidrs == (NET("10.0.0.0/24"),)

    def test_all_addresses_of_selected_domain_covered(self):
        plan = build_plan(
            ["10.0.0.0/24"], [D("multi", "10.0.0.1", "10.0.2.1", "10.0.2.2")], 3
        )
        assert plan.selected_domains == ("multi",)
        listed = address_set(plan.cidrs)
        assert {ipaddress.ip_address("10.0.0.1"),
                ipaddress.ip_address("10.0.2.1"),
                ipaddress.ip_address("10.0.2.2")} <= listed

    def test_adjacent_address_requires_extra_rule(self):
        # 10.0.1.1 与 10.0.0.0/24 相邻但不能聚合为 /23（会多放行 .0/24 中
        # 未列出的地址），所以需要 /32，共 2 条
        plan = build_plan(["10.0.0.0/24"], [D("a", "10.0.1.1")], 2)
        assert [str(n) for n in plan.cidrs] == ["10.0.0.0/24", "10.0.1.1/32"]
        assert plan.coverage.exact is True

    def test_feasible_without_migration(self):
        plan = build_plan(["10.0.0.0/24"], [D("a", "10.1.0.1")], 1)
        assert plan.feasible is True
        assert plan.migration_possible is False
        assert plan.selected_domains == ()
        assert [str(n) for n in plan.cidrs] == ["10.0.0.0/24"]
        assert "没有可迁移域名" in plan.message

    def test_no_solution_when_current_whitelist_already_too_large(self):
        plan = build_plan(
            ["10.0.0.0/24", "10.0.2.0/24"], [D("a", "10.1.0.1")], 1
        )
        assert plan.feasible is False
        assert plan.migration_possible is False
        assert plan.cidrs == ()
        assert plan.rule_count is None
        assert "无可行方案" in plan.message
        assert plan.current_rule_count == 2

    def test_no_solution_when_cap_zero_and_whitelist_nonempty(self):
        plan = build_plan(["10.0.0.0/24"], [], 0)
        assert plan.feasible is False
        assert plan.cidrs == ()

    def test_empty_address_group_rejected(self):
        with pytest.raises(PlanError, match="地址组为空"):
            build_plan(["10.0.0.0/24"], [("empty", [])], 5)

    def test_duplicate_ips_deduplicated(self):
        plan = build_plan(
            ["10.0.0.0/24"], [D("a", "10.1.0.1", "10.1.0.1")], 2
        )
        assert plan.selected_domains == ("a",)
        assert plan.rule_count == 2

    def test_current_whitelist_collapsed_to_minimum(self):
        # 配置了 2 条但等价于 1 条：结果按最小精确表示返回
        plan = build_plan(
            ["10.0.0.0/25", "10.0.0.128/25"], [D("a", "10.1.0.1")], 2
        )
        assert [str(n) for n in plan.cidrs] == ["10.0.0.0/24", "10.1.0.1/32"]
        assert plan.current_rule_count == 1
        assert plan.coverage.exact is True

    def test_domains_inside_current_whitelist_cost_nothing(self):
        plan = build_plan(
            ["10.0.0.0/24"],
            [D(f"d{i}", f"10.0.0.{i}") for i in range(1, 13)],
            1,
        )
        assert len(plan.selected_domains) == 12
        assert [str(n) for n in plan.cidrs] == ["10.0.0.0/24"]

    @pytest.mark.parametrize(
        ("current", "domains", "cap", "match"),
        [
            (["10.0.0.0/24"], [D("a", "10.1.0.1")], -1, "不能为负"),
            (["bad"], [D("a", "10.1.0.1")], 2, "非法 CIDR"),
            (["2001:db8::/32"], [D("a", "10.1.0.1")], 2, "IPv6"),
            (["10.0.0.0/24"], [D("a", "2001:db8::1")], 2, "IPv6"),
            (["10.0.0.0/24"], [D("a", "not-an-ip")], 2, "非法 IP"),
            (["10.0.0.0/24"], [D("a", "10.1.0.1"), D("a", "10.1.0.2")], 2, "重复"),
            (
                ["10.0.0.0/24"],
                [D(f"d{i}", "10.1.0.1") for i in range(13)],
                2,
                "最多 12 个",
            ),
        ],
    )
    def test_invalid_input_rejected(self, current, domains, cap, match):
        with pytest.raises(PlanError, match=match):
            build_plan(current, domains, cap)


class TestDomainValidation:
    @pytest.mark.parametrize(
        "good",
        ["a.test", "_dmarc.a.test", "exa-mple.test", "*.example.test", "localhost"],
    )
    def test_accepts_valid_shapes(self, good):
        assert normalize_domain(good) == good

    @pytest.mark.parametrize("bad", ["a..b", "例子.test", "-a.test", "a b.test"])
    def test_rejects_invalid_shapes(self, bad):
        with pytest.raises(PlanError):
            normalize_domain(bad)

    def test_address_group_limit(self):
        with pytest.raises(PlanError, match="地址组超过"):
            build_plan(["10.0.0.0/24"], [D("a", *(["10.0.0.1"] * 257))], 5)

    def test_total_address_limit(self):
        domains = [
            (f"d{i}", [f"10.{i}.0.{j}" for j in range(1, 256)]) for i in range(5)
        ]
        # 5 * 255 > 1024
        with pytest.raises(PlanError, match="地址总数超过"):
            build_plan(["10.0.0.0/24"], domains, 5000)


class TestExactness:
    def test_candidate_fills_hole_and_allows_collapse(self):
        # 当前 10.0.0.0/25 + 域名地址 10.0.0.128..255 -> 恰好可写成 1 条 /24
        plan = build_plan(
            ["10.0.0.0/25"],
            [D("a", *[f"10.0.0.{i}" for i in range(128, 256)])],
            1,
        )
        assert plan.selected_domains == ("a",)
        assert [str(n) for n in plan.cidrs] == ["10.0.0.0/24"]
        assert plan.coverage.exact is True

    def test_partial_hole_fill_stays_two_rules(self):
        # 只补齐一个地址（.128）时仍不能聚合为 /24（会多放行 .129..254）
        plan = build_plan(["10.0.0.0/25"], [D("a", "10.0.0.128")], 1)
        assert plan.selected_domains == ()
        assert [str(n) for n in plan.cidrs] == ["10.0.0.0/25"]

    def test_hole_not_filled_stays_two_rules(self):
        plan = build_plan(["10.0.0.0/25"], [D("a", "10.0.0.129")], 1)
        assert plan.selected_domains == ()
        assert [str(n) for n in plan.cidrs] == ["10.0.0.0/25"]

    def test_no_overbroad_aggregation_across_gap(self):
        # 10.0.0.1 与 10.0.0.3 之间缺 .2，不能合并为 /30（会多放行 .0/.2）
        plan = build_plan([], [D("a", "10.0.0.1", "10.0.0.3")], 5)
        listed = address_set(plan.cidrs)
        assert listed == {ipaddress.ip_address("10.0.0.1"), ipaddress.ip_address("10.0.0.3")}

    def test_result_uses_broadest_exact_cidrs(self):
        plan = build_plan(
            [], [D("a", *[f"10.0.0.{i}" for i in range(1, 255)])], 20
        )
        assert plan.coverage.exact is True
        assert address_set(plan.cidrs) == {
            ipaddress.ip_address(f"10.0.0.{i}") for i in range(1, 255)
        }
        # 最小表示：.1/32、.2/31、.4/30 ... .254/32，共 14 条
        assert plan.rule_count == 14
