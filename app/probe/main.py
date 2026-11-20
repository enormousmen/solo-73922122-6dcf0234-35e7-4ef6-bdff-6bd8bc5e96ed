"""FastAPI 出站探测 API。

* 全异步实现，慢探测不会阻塞事件循环与其他请求；
* 并发量由信号量保护，超出立即返回 429，不排队堆积；
* 单次探测有总超时，超时返回 408 并附带已完成的逐跳信息；
* 另提供只读的白名单迁移规划接口（纯计算，不发起网络请求、不修改配置）。
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from dataclasses import asdict

from fastapi import Body, FastAPI, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from .config import Settings, load_settings
from .dns_client import DnsResolver
from .http_probe import Prober
from .planner import PlanError, build_plan
from .policy import PolicyError


class ProbeRequest(BaseModel):
    url: str = Field(..., description="待探测的 http/https URL")
    method: str = Field("GET", description="HTTP 方法，仅支持 GET/HEAD")


class TlsReport(BaseModel):
    version: str
    cipher: str
    subject: str
    san: list[str]
    peer_cert_subject: str


class HopReportModel(BaseModel):
    hop: int = Field(..., description="跳序号，从 1 开始")
    url: str = Field(..., description="本跳请求的完整 URL")
    scheme: str
    hostname: str = Field(..., description="URL 中的主机名（证书校验与 Host 头均用它）")
    port: int
    resolved_addresses: list[str] = Field(
        ..., description="DNS 实际返回的全部 A 记录（IPv4）"
    )
    approved_addresses: list[str] = Field(
        ..., description="通过白名单校验的地址；整体被拒时为空列表"
    )
    connected_peer: str | None = Field(
        None, description="实际建立 TCP 连接的 ip:port，固定为已批准地址；未连接为 null"
    )
    tls: dict | None = Field(None, description="HTTPS 时的 TLS 版本、套件与证书信息")
    request_sent: bool = Field(
        ..., description="是否真正发出 HTTP 请求；被策略拒绝时恒为 false"
    )
    status_code: int | None = Field(None, description="HTTP 响应状态码")
    reason: str | None
    location: str | None = Field(None, description="3xx 响应的 Location 头")
    redirect_count: int
    outcome: str = Field(
        ..., description="ok | redirected | blocked | error"
    )
    reject_reason: str | None = Field(None, description="策略拒绝原因（面向白名单调整）")
    error: str | None = Field(None, description="连接/TLS/读取等错误原因")


class ProbeResponse(BaseModel):
    requested_url: str
    method: str
    outcome: str = Field(..., description="ok | blocked | error | timeout")
    summary: str = Field(..., description="人类可读的结论摘要")
    hops: list[HopReportModel] = Field(..., description="逐跳探测报告")
    allowed_cidrs: list[str] = Field(..., description="本次启动生效的 IPv4 白名单")
    dns_server: str
    max_redirects: int
    elapsed_ms: int = Field(..., description="整次探测耗时（毫秒）")


class PolicyResponse(BaseModel):
    allowed_cidrs: list[str]
    dns_server: str
    dns_port: int
    ip_versions: list[str]
    max_redirects: int
    tls_verify: bool
    ca_bundle: str | None
    timeouts: dict


class PlanDomainInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(..., description="回调域名（去重后参与规划）")
    addresses: list[str] = Field(
        ...,
        min_length=1,
        description=(
            "探测报告里的完整 IPv4 地址组（必须全部列出，不能只给部分）；"
            "至少 1 个地址，空组表示无法确认，将以 422 拒绝"
        ),
    )


class PlanRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "max_cidrs": 2,
                    "domains": [
                        {
                            "domain": "hooks.a.demo.test",
                            "addresses": ["172.31.10.20"],
                        },
                        {
                            "domain": "hooks.b.demo.test",
                            "addresses": ["203.0.113.20", "203.0.113.21"],
                        },
                    ],
                }
            ]
        },
    )

    domains: list[PlanDomainInput] = Field(
        ...,
        max_length=12,
        description="待迁移回调域名，最多 12 个；每个域名必须给出全部 IPv4 地址",
    )
    max_cidrs: int = Field(
        ...,
        ge=0,
        description="设备能容纳的 CIDR 总条数（结果清单不得超过该值）",
    )
    current_cidrs: list[str] | None = Field(
        None,
        description=(
            "当前设备上生效的 IPv4 白名单；省略时使用本服务配置的 ALLOWED_CIDRS。"
            "仅在演练“若白名单是另一组值”时显式传入，规划始终精确保留其覆盖率"
        ),
    )


class PlanCandidateModel(BaseModel):
    domain: str
    addresses: list[str]
    selected: bool
    reason: str


class PlanCoverageModel(BaseModel):
    exact: bool = Field(..., description="清单覆盖范围是否恰好等于所需并集")
    covers_current_whitelist: bool
    selected_domains_fully_covered: bool
    listed_address_count: int
    expected_union_address_count: int


class PlanResponse(BaseModel):
    feasible: bool = Field(
        ..., description="是否存在满足上限、且精确保留当前放行范围的清单"
    )
    migration_possible: bool = Field(
        ..., description="是否存在至少迁移一个域名的可行方案（即返回值是否非空）"
    )
    selected_domains: list[str] = Field(
        ..., description="可迁移域名（每个域名的全部地址都被清单覆盖）"
    )
    cidrs: list[str] = Field(
        ..., description="可替换当前白名单的 CIDR 清单（精确覆盖并集，条数不超过上限）"
    )
    rule_count: int | None = Field(
        None, description="清单条数；无可行方案时为 null"
    )
    max_cidrs: int
    current_configured_cidrs: list[str] = Field(
        ..., description="提交时声明的当前白名单（原样）"
    )
    current_exact_cidrs: list[str] = Field(
        ..., description="当前白名单的最小精确 CIDR 表示（结果清单的基础）"
    )
    current_rule_count: int = Field(..., description="当前白名单的最小精确 CIDR 条数")
    candidates: list[PlanCandidateModel] = Field(
        ..., description="每个候选域名的入选与否及原因"
    )
    coverage: PlanCoverageModel = Field(..., description="对清单覆盖范围的独立核对")
    read_only: bool = Field(
        True, description="本接口为只读规划：不发起网络请求、不修改任何配置"
    )
    current_cidrs_source: str = Field(
        ...,
        description="current_cidrs 的来源：request（请求体显式传入）或 configured（ALLOWED_CIDRS）",
    )
    message: str = Field(..., description="面向值班员的人类可读结论")


settings: Settings = load_settings()
resolver = DnsResolver(
    settings.dns_server,
    port=settings.dns_port,
    timeout=settings.dns_timeout,
    retries=settings.dns_retries,
)
prober = Prober(
    policy=settings.policy,
    resolver=resolver,
    ca_bundle=settings.ca_bundle,
    connect_timeout=settings.connect_timeout,
    read_timeout=settings.read_timeout,
    tls_timeout=settings.tls_timeout,
    max_redirects=settings.max_redirects,
)
_semaphore = asyncio.Semaphore(settings.max_concurrency)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(
    title="出站探测 API（Egress Probe）",
    version="1.0.0",
    description=(
        "提交 HTTP/HTTPS URL，返回逐跳状态、DNS 解析地址、实际连接地址与拒绝原因。"
        "仅支持 IPv4；每跳全部解析地址均在启动时配置的 CIDR 白名单内才会连接；"
        "最多跟随 3 次跳转；被拒目标不会收到任何探测请求；HTTPS 始终按原域名验证证书。"
    ),
    lifespan=lifespan,
)


@app.get("/healthz", tags=["meta"])
async def healthz() -> dict:
    return {"status": "ok", "service": "egress-probe"}


@app.get("/api/v1/policy", response_model=PolicyResponse, tags=["meta"])
async def get_policy() -> PolicyResponse:
    return PolicyResponse(
        allowed_cidrs=settings.allowed_cidrs,
        dns_server=settings.dns_server,
        dns_port=settings.dns_port,
        ip_versions=["IPv4"],
        max_redirects=settings.max_redirects,
        tls_verify=True,
        ca_bundle=settings.ca_bundle,
        timeouts={
            "dns": settings.dns_timeout,
            "connect": settings.connect_timeout,
            "tls": settings.tls_timeout,
            "read": settings.read_timeout,
            "overall": settings.overall_timeout,
        },
    )


@app.post(
    "/api/v1/whitelist/plans",
    response_model=PlanResponse,
    tags=["plan"],
    summary="只读规划：在 CIDR 上限内最大化可迁移域名数",
)
async def create_whitelist_plan(
    req: PlanRequest = Body(
        ...,
        openapi_examples={
            "demo_merged": {
                "summary": "演示：域名地址落在现有白名单内，零新增规则",
                "description": (
                    "probe 容器配置的白名单是 172.31.10.0/24（省略 current_cidrs）。"
                    "hooks.allowed.demo.test 解析到该网段内，直接被现有清单覆盖；"
                    "hooks.external.demo.test 在 203.0.113.0/24，需要额外 1 条 /32。"
                ),
                "value": {
                    "max_cidrs": 2,
                    "domains": [
                        {
                            "domain": "hooks.allowed.demo.test",
                            "addresses": ["172.31.10.10"],
                        },
                        {
                            "domain": "hooks.external.demo.test",
                            "addresses": ["203.0.113.20", "203.0.113.21"],
                        },
                    ],
                },
            },
            "demo_no_solution": {
                "summary": "无可行方案：当前白名单精确表示已超过上限",
                "description": (
                    "现有白名单 10.0.0.0/24 与 10.0.2.0/24 之间存在空洞，"
                    "最小精确表示需要 2 条 CIDR，而设备只能放 1 条，"
                    "因此 feasible=false、cidrs 为空。"
                ),
                "value": {
                    "current_cidrs": ["10.0.0.0/24", "10.0.2.0/24"],
                    "max_cidrs": 1,
                    "domains": [
                        {"domain": "hooks.example.test", "addresses": ["10.1.0.1"]}
                    ],
                },
            },
            "demo_tradeoff": {
                "summary": "上限内域名数优先、其次规则更少",
                "description": (
                    "三个域名中，上限 3 条时最优先选 2 个域名（占满 3 条）；"
                    "单个域名虽只需 2 条，但域名数更少，故不采用。"
                ),
                "value": {
                    "current_cidrs": ["10.0.0.0/24"],
                    "max_cidrs": 3,
                    "domains": [
                        {"domain": "two-rules.test", "addresses": ["10.5.0.1", "10.7.0.1"]},
                        {"domain": "one-rule-a.test", "addresses": ["10.1.0.1"]},
                        {"domain": "one-rule-b.test", "addresses": ["10.2.0.1"]},
                    ],
                },
            },
        },
    ),
) -> PlanResponse:
    """只读规划：在保留现有放行范围的前提下，最大化可迁移域名数。

    * 结果清单的覆盖范围恰好是“当前白名单 ∪ 入选域名全部地址”，不多不少；
    * 域名只有在其全部地址都被覆盖时才可入选；
    * 在 CIDR 上限内优先选域名最多，其次选规则更少；无可行方案时
      ``feasible=false``、清单为空并在 ``message`` 中说明原因；
    * 不发起任何 DNS/HTTP 请求，也不修改白名单配置。
    """
    current_cidrs = (
        req.current_cidrs
        if req.current_cidrs is not None
        else settings.allowed_cidrs
    )
    try:
        # 组合枚举是 CPU 密集的纯计算，放到线程池避免阻塞探测事件循环
        plan = await run_in_threadpool(
            build_plan,
            current_cidrs=current_cidrs,
            domains=[(d.domain, d.addresses) for d in req.domains],
            max_cidrs=req.max_cidrs,
        )
    except PlanError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return PlanResponse(
        feasible=plan.feasible,
        migration_possible=plan.migration_possible,
        selected_domains=list(plan.selected_domains),
        cidrs=[str(net) for net in plan.cidrs],
        rule_count=plan.rule_count,
        max_cidrs=plan.max_cidrs,
        current_configured_cidrs=[str(net) for net in plan.current_configured_cidrs],
        current_exact_cidrs=[str(net) for net in plan.current_exact_cidrs],
        current_rule_count=plan.current_rule_count,
        candidates=[
            PlanCandidateModel(
                domain=c.domain,
                addresses=list(c.addresses),
                selected=c.selected,
                reason=c.reason,
            )
            for c in plan.candidates
        ],
        coverage=PlanCoverageModel(
            exact=plan.coverage.exact,
            covers_current_whitelist=plan.coverage.covers_current_whitelist,
            selected_domains_fully_covered=(
                plan.coverage.selected_domains_fully_covered
            ),
            listed_address_count=plan.coverage.listed_address_count,
            expected_union_address_count=(
                plan.coverage.expected_union_address_count
            ),
        ),
        read_only=True,
        current_cidrs_source=(
            "request" if req.current_cidrs is not None else "configured"
        ),
        message=plan.message,
    )


@app.post("/api/v1/probe", response_model=ProbeResponse, tags=["probe"])
async def create_probe(req: ProbeRequest) -> ProbeResponse:
    method = req.method.upper()
    if method not in ("GET", "HEAD"):
        raise HTTPException(status_code=422, detail="仅支持 GET/HEAD 方法")

    started = time.monotonic()
    # 单事件循环内，locked() 检查与后续 acquire 之间没有 await，判定是原子的
    if _semaphore.locked():
        raise HTTPException(
            status_code=429,
            detail=(
                f"探测并发已达上限 {settings.max_concurrency}，"
                "为避免慢探测互相阻塞，请求被拒绝，请稍后重试"
            ),
        )

    async with _semaphore:
        try:
            hops = await asyncio.wait_for(
                prober.probe(req.url, method=method),
                timeout=settings.overall_timeout,
            )
        except PolicyError as exc:
            # 入口级静态错误（如非法 URL）：未产生任何流量
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except asyncio.TimeoutError:
            elapsed = int((time.monotonic() - started) * 1000)
            raise HTTPException(
                status_code=408,
                detail={
                    "message": f"探测总超时（{settings.overall_timeout}s）",
                    "elapsed_ms": elapsed,
                },
            ) from None

    elapsed_ms = int((time.monotonic() - started) * 1000)
    last = hops[-1]
    if last.outcome == "blocked":
        outcome = "blocked"
        summary = f"第 {last.hop} 跳被策略拒绝: {last.reject_reason}"
    elif last.outcome == "error":
        outcome = "error"
        summary = f"第 {last.hop} 跳出错: {last.error}"
    else:
        outcome = "ok"
        summary = f"探测完成，共 {len(hops)} 跳，最终状态码 {last.status_code}"

    return ProbeResponse(
        requested_url=req.url,
        method=method,
        outcome=outcome,
        summary=summary,
        hops=[HopReportModel(**asdict(h)) for h in hops],
        allowed_cidrs=settings.allowed_cidrs,
        dns_server=f"{settings.dns_server}:{settings.dns_port}",
        max_redirects=settings.max_redirects,
        elapsed_ms=elapsed_ms,
    )
