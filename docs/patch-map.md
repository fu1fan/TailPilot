# TailPilot 补丁维护索引

本索引按公开 R6 基线及 CNB 迁移分支整理。上游基线为 `v1.102.3`，
对应提交 `53a0d659afa51835dd7a9283873cca44261454f8`。
表中列出关键入口与代表性测试，不把文件存在视为测试通过，也不穷举所有修改。

## 功能、源码与升级检查

| 功能 | 主要实现 | 接入上游的位置／升级时检查 | 代表性回归 |
| --- | --- | --- | --- |
| 配置、功能开关和策略代次 | `featurepolicy/`、`ipn/ipnlocal/unified_policy.go`、`unified_identity.go` | `ipn/ipnlocal/local.go`、`profiles.go`：启动、退出、身份切换和策略消费者；检查旧代次不能提交新状态 | `featurepolicy/manager_test.go`、`ipn/ipnlocal/unified_policy_test.go`、`unified_identity_test.go` |
| DNS 租约与 TTL | `appc/lease*.go`、`observe_lease.go`、`provenance.go` | `appc/appconnector.go`、`observe.go`：域名分配、DNS 观察和到期撤销；检查共享 IP 所有权、时钟确认及 TTL 更新 | `appc/lease_controller_test.go`、`lease_time_confirmation_test.go`、`observe_lease_test.go` |
| DNS 只返回 IPv4，但学习 IPv6 路由 | `appc/dnspolicy.go`、`ipn/ipnlocal/unified_dns.go` | `ipn/ipnlocal/peerapi.go`、`net/dns/resolver/tsdns.go`：原始 DNS 答案供路由学习，客户端答案过滤 AAAA；检查转发、取消、队列和提交时序 | `appc/dnspolicy_test.go`、`ipn/ipnlocal/unified_dns_dualstack_test.go`、`unified_dns_queue_test.go`、`unified_dns_transport_test.go`、`net/dns/resolver/tsdns_peerdns_test.go` |
| 清理、路由归属及重启恢复 | `ipn/ipnlocal/routeledger.go`、`unified_clear.go`、`unified_handoff.go`、`unified_takeover*.go`、`unified_prefs.go` | `local.go` 的偏好更新与路由发布、`ipn/store/stores.go` 的持久化；检查手动／控制面路由保留、已清理路由不复活、已确认租约不丢失 | `unified_clear_test.go`、`unified_handoff_recovery_test.go`、`unified_recovery_fence_test.go`、`unified_readvertise_test.go`、`ipn/store/atomic_states_test.go` |
| 活动观察 | `appc/activity*.go`、`net/tstun/unified_activity.go` | `net/tstun/wrap.go`：检查观察发生于被接受的数据包路径，方向和身份判断不被上游移动 | `appc/activity_packets_test.go`、`net/tstun/unified_activity_test.go` |
| direct／peer-relay／DERP 路径策略 | `featurepolicy/path.go`、`wgengine/magicsock/pathpolicy*.go`、`authenticated_path.go` | `magicsock.go`、`endpoint.go`、`derp.go`、`relaymanager.go`：发送选择、接收认证及连接更新；检查禁止路径、允许路径和回退行为 | `pathpolicy_test.go`、`pathpolicy_receive_test.go`、`authenticated_path_test.go`；真实跨网路径仍需原生环境验证 |
| WireGuard 已认证接收入口 | `third_party/wireguard-go/PATCH.diff` | 根 `go.mod` 的本地替换、嵌套模块的接收处理；检查认证成功后才产生策略副作用，不能仅靠解决文本冲突 | `third_party/wireguard-go/verify_patch.py` 及该嵌套模块测试；具体基线与许可证见 [PATCH.md](../third_party/wireguard-go/PATCH.md) |
| 管理与诊断命令 | `cmd/tailscale/cli/appc_route.go`、`unified_policy.go`、`ipn/localapi/unified_debug.go` | `cmd/tailscale/cli/debug.go`、`ipn/localapi/debug.go`、`client/local/local.go`：请求字段、权限、预览与执行的代次检查 | `cmd/tailscale/cli/appc_route_test.go`、`unified_policy_test.go`、`ipn/localapi/unified_debug_test.go` |
| 测试、构建与部署工具 | `lab/`、`release/`、`deploy/`、`.ci/`、`.cnb.yml` | Go 版本、基线标签／提交、构建脚本校验、状态兼容与回滚契约；不随 CI 自动部署生产 | [CNB 流程](CNB.md)、各工具目录的测试与说明 |

当前相对基线的 `derp/` 和 `cmd/derper/` 没有修改。路径控制主要位于
`tailscaled` 的 magicsock 层；表中的 `wgengine/magicsock/derp.go` 不是 DERP 服务端。
客户端保持原版是集成测试的约束，不能用第二个修改版 daemon 代替原版客户端作为证明。

## 如何取得完整改动范围

在仓库根目录执行：

```sh
# 完整文件清单，区分修改已有文件和新增文件。
git diff --name-status v1.102.3 HEAD
# 优先审查已有上游文件的修改；新增模块另行检查。
git diff --diff-filter=M --name-only v1.102.3 HEAD
# 查看具体接入点。
git diff v1.102.3 HEAD -- ipn/ipnlocal/peerapi.go wgengine/magicsock/endpoint.go
# 嵌套 WireGuard 是导入的依赖，不能把全部新增文件都算成自研改动。
python3 third_party/wireguard-go/verify_patch.py
```

升级基线后，上述比较基线与本页必须一起更新。不要用“文件名没有冲突”推断语义兼容。
`drive.go`、`tailnet-lock.go` 等表外改动同样要通过完整差异清单审查。

## 后续提交约定

1. 一个提交尽量只改变一个功能或一个独立维护事项；对应测试随实现提交。
   DNS、TTL、路径策略、构建和纯文档不要无关地混成一个提交。
2. 上游版本引入、兼容性调整、功能变化分别提交。提交说明写清受影响的入口、
   保持的行为、验证结果和未验证边界；跨模块但不可分割的功能允许放在同一提交。
3. 修改上游接入点时更新本表；新增关键回归测试时加入对应行。
4. 两台服务器使用同一程序，通过配置区分角色，不复制两套源码。
5. 不重写已公开历史来人为拆分旧提交。公开 R6 基线是一个脱敏汇总提交，
   无法直接按私有历史中的小提交逐一重放；私有历史不要推送到公开仓库。
6. 不为集中存放而搬动源码，也不新增一份容易失配的完整补丁副本。
   根仓库以 Git 差异为准；嵌套 WireGuard 继续维护现有 `PATCH.diff`。

## 上游升级顺序

先记录当前提交与候选上游版本，在独立升级分支比较完整差异；引入新版本并按本表逐项
审查接入点，再更新 Go、原版测试客户端及 release 脚本中的固定基线校验。
运行对应模块测试、CNB race／用户态回归和冷启动突发压测；路径、内核转发、NAT 和
实际 IPv6 出口另做原生验证。CI 通过不代表生产验收或自动授权部署。

新增提交可用 `git range-diff` 辅助检查升级前后的改动系列；对汇总基线还需直接比较文件
和行为。不要套用旧文档里“重放每个 unified 提交”的做法，假定公开仓库保留了那段历史。
