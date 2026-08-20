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

1. Make your change inside a lokal checkout of
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
| `http_add_uot.patch` | HTTP outbound gains `udp_over_tcp` option (UDP over TCP, same mechanism as socks/shadowsocks) |
| `make_log_better_log.patch` | Log timestamp format `[2006-01-02 15:04:05 UTC-07]` |

### reF1nd_Stable/ + reF1nd_Testing/

| Patch | Effect |
|---|---|
| `urltest-autoban.patch` | **urltest 智能健康淘汰（AutoBan v4.3）**：`auto_ban` 配置块——EWMA 动态健康评分 + 被动单次失败熔断 + 主动指数退避恢复 + 多目标 204 竞速探针 + TUN Protected Dialer + I/O 防抖 + 多 Group Hash 文件隔离。不再依赖固定 `check_times` 裁决生死；状态持久化默认 `autoban_<group>_<hash>.json`（filemanager→SFA 工作目录）。本地原创设计（非上游移植） |
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
    "fail_threshold": 5,
    "path": "",
    "probe_urls": [
      "http://connect.rom.miui.com/generate_204",
      "http://connectivitycheck.platform.hicloud.com/generate_204",
      "http://cp.cloudflare.com/generate_204",
      "http://www.gstatic.com/generate_204"
    ],
    "probe_timeout": "5s",
    "recovery_interval": "1m",
    "initial_backoff": "1m",
    "max_backoff": "30m",
    "ban_threshold": 25,
    "recover_threshold": 60,
    "max_latency": "1000ms",
    "recover_successes": 2,
    "flush_delay": "3s"
  }
}
```

> All patches verified against `reF1nd-stable` / `reF1nd-testing` (2026-08-12),
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

