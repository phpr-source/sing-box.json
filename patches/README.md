# Patches

This directory contains **build-time patches** applied to the sing-box core source code
before compilation. Patches are applied on the fly by the CI workflow — no fork needed.

## Directory Layout

```
patches/
  README.md
  common/           # Applied to ALL targets (Stable + Testing)
    *.patch
  reF1nd_Stable/    # Applied ONLY to reF1nd_Stable builds
    *.patch
  reF1nd_Testing/   # Applied ONLY to reF1nd_Testing builds
    *.patch
```

## How to Add a Patch

1. Make your change inside a local checkout of
   [`reF1nd/sing-box`](https://github.com/reF1nd/sing-box).
2. Generate the patch:
   ```bash
   git diff > my-change.patch
   # or for a single commit:
   git format-patch -1 HEAD
   ```
3. Place the `.patch` file in the appropriate subdirectory above.
4. Commit and push. The workflow applies it automatically.

## Patch Requirements

- **Path-relative to sing-box root.** A diff hunk referencing
  `a/cmd/sing-box/main.go` is applied to
  `sing-box/cmd/sing-box/main.go` inside the CI checkout.
- **Must apply cleanly.** Patch failure is a hard build error.
  If upstream code changes break the patch, update or remove it.
- **Plain `git diff` format.** Context lines, hunks, standard unified diff.

## Verification

After adding a patch, trigger a `workflow_dispatch` build and verify
the "Apply Patches" step in the log:

```
::notice::Applying patch my-change.patch
Applied 1 patch(es).
```

If a patch fails, the build stops immediately with an error showing
which file/hunk conflicted.

## Current Patches

### common/ (all targets)

| Patch | Effect |
|---|---|
| `xhttp-core-directories.patch` | VLESS XHTTP 支持（新增目录）：`common/xray/`（XRAY 基础设施 50 文件）+ `common/congestion/` + `common/kmutex/`。来源：shtorm-7/sing-box-extended（extended 分支） |
| `change_default_urltest.patch` | Default urltest URL `www.gstatic.com/generate_204` → `cp.cloudflare.com/generate_204` (more reachable in CN networks) |
| `make_log_better_log.patch` | Log timestamp format `[2006-01-02 15:04:05 UTC-07]` |
| `fallback-group.patch` | **fallback 策略组**（新增组类型）：`constant/proxy.go`（`TypeFallback`）+ `include/registry.go` + `option/group.go`（`FallbackOutboundOptions`，`blacklist_timeout` 为**指针**：省略 = 默认 1 分钟，显式 `0` = 真正禁用黑名单，负数报错）+ `protocol/group/fallback.go`（按 tag 顺序轮询，失败节点进黑名单，兜底轮忽略黑名单；`ctx.Err() != nil` 视为客户端侧取消、不拉黑）。**注意**：该补丁必须先于 `provider-fallback-dependency.patch` 应用（后者引用本补丁引入的 `option.FallbackOutboundOptions`），文件名字母序已满足 |
| `provider-fallback-dependency.patch` | provider 拓扑排序补齐 `*option.FallbackOutboundOptions` 依赖（`adapter/provider/update.go` 的 `visit` switch 只列了 selector/loadbalance/urltest 三种组）——缺此 case 时 provider 携带的 fallback 组收集不到成员依赖，会被排在成员之前安装并直接报 `outbound N not found`。同时新增回归测试 `adapter/provider/group_dependency_test.go`（5 用例，含 selector 对照组与「成员必须写全限定 `<provider>/<tag>`」契约） |

### reF1nd_Stable/ + reF1nd_Testing/

| Patch | Effect |
|---|---|
| `fallback-group-lifecycle.patch` | fallback 组的作用域化生命周期适配（per-branch variant）：把 `Start() error` 换成 `Start(stage adapter.StartStage, scope *adapter.Scope) error`。2026-10-10 上游从 `adapter/outbound.Manager.startOutbounds` 删除了 plain-starter 分支（现在只认 `adapter.Lifecycle`，其它类型静默 `continue`），旧 shim 不再被调用、成员表永不解析。**分支差异**：testing 版额外含 `OnConnectionFailure` 的 chain 归因实现 |
| `urltest-autoban.patch` | **urltest 智能健康淘汰（AutoBan v4.6）**：`auto_ban` 配置块——EWMA 动态健康评分 + 被动单次失败熔断 + 主动指数退避恢复 + 每日固定时段全局大考（`check_times`）+ 群体故障防误杀 + 多目标 HTTPS 204 竞速探针 + TUN Protected Dialer + I/O 防抖 + 多 Group Hash 文件隔离 + `pinned_tags` 手动选择豁免。状态持久化默认 `autoban_<group>_<hash>.json`。本地原创设计（非上游移植）。**分支差异**：testing 版适配 2026-09-27 上游 `RealTag(detour, network)` 新签名（嵌套组按 network 解析；无 network 上下文用 `N.NetworkTCP` 规范键）与 `urltest_unified_delay` API |
| `http_add_uot.patch` | HTTP outbound gains `udp_over_tcp` option (UDP over TCP, same mechanism as socks/shadowsocks)。**分支差异**：stable 版作用于仅 TCP 的旧实现；testing 版上游 HTTP 代理已重写（H2/H3、原生 TCP+UDP 注册），移植版保留原生 UDP 行为，仅在 `udp_over_tcp.enabled` 时把 UDP 流量切入 UoT 隧道。2026-10-01 因两分支结构分叉从 `common/` 拆分为 per-branch 变体 |
| `xhttp-wiring.patch` | XHTTP 接入：`transport/v2rayxhttp/`（10 文件）+ `constant/v2ray.go`（+`xhttp` 类型）+ `option/v2ray_transport.go`（XHTTP 选项，含本地 `Range[T]` 替代私有 sing fork 的 `badoption.Range`）+ `option/range.go` + `transport/v2ray/transport.go` 注册 + `transport/v2rayhttp/conn.go`（HWIDContext）。**分支差异**：testing 版适配 sing-quic v0.7 API（`qtls.DialEarly` 签名变化），stable 版用 v0.6；testing 版含 `DescribeSchema` 变体 |
| `make_log_better_option.patch` | Expose `disable_color` as a JSON log option (per-branch variant: branch layouts differ) |

#### AutoBan 使用示例

```json
{
  "type": "urltest",
  "tag": "auto",
  "outbounds": ["节点A", "节点B"],
  "auto_ban": {
    "enabled": true,
    "check_times": ["08:00", "12:00", "20:00"],
    "fail_threshold": 5,
    "path": "",
    "probe_urls": [
      "https://connect.rom.miui.com/generate_204",
      "https://connectivitycheck.platform.hicloud.com/generate_204"
    ],
    "probe_timeout": "3s",
    "recovery_interval": "1m",
    "initial_backoff": "1m",
    "max_backoff": "30m",
    "ban_threshold": 25,
    "recover_threshold": 60,
    "max_latency": "1000ms",
    "recover_successes": 2,
    "flush_delay": "3s",
    "pinned_tags": ["手动保底节点"]
  }
}
```

> All patches verified against `reF1nd-stable` / `reF1nd-testing` (2026-08-21),
> source: [yagh779/sing-box-releases](https://github.com/yagh779/sing-box-releases) (patches branch),
> regenerated against current upstream. `null_ip_reject.patch` from the same source
> was **not** adopted (DNS reply semantics, upstream itself leaves it unapplied).
>
> **XHTTP 维护说明**：xhttp 系列 patch 来源为
> [shtorm-7/sing-box-extended](https://github.com/shtorm-7/sing-box-extended)
> （钉版 commit `e8f69364`，extended 分支）。本地适配点：
> ① `badoption.Range` 本地化为 `option/range.go`（官方 sing 无此类型）；
> ② `xhttp.NewClient` 去除 logger 参数（reF1nd 构造器类型无 logger）；
> ③ testing 版适配 sing-quic v0.7 API。上游修复或 reF1nd 基线变化时：
> 重新执行"干净 clone → 应用 → 编译 → git diff 重生成"流程，或手工合并。
> check-patches.yml 每日自动验证可应用性。

