"""
融合与告警分级 —— 决定"哪些能叫醒安全员"。

三个输入
--------
1. host  : 主机内通道（风扇 PWM / 指示灯 / 功耗读数），来自 collectors/
2. phys  : 带外物理通道（房间麦克风 / 光电探头 / 电源侧传感器），来自 out-of-band 盒子
3. writes: 进程级 PWM 写入日志，来自 attribution 的采样器

输出策略（这是压误报的关键，比检测算法本身更重要）
--------------------------------------------------
* 分级：只有 CONFIRMED 与 HIGH 进入值班队列；MEDIUM 进日报；LOW 只存证。
* 去重：同一对通道在窗口期内只报一次，后续只累加 count（避免"每秒一条"刷屏）。
* 抑制：命中已学习的良性剖面（热控爬升、编译满载）直接降级到 INFO。
* 证据链不完备时**降级而不是升级**——宁可漏报一次让日报兜底，
  也不要让值班员一夜被同一件事叫醒 200 次（那会导致真正告警被忽略）。

这是刻意的不对称设计：假阴性由"日报 + 周期性人工巡检"补偿，
假阳性由"物理确认门槛"压到底。在保密单位，值班员的注意力是最稀缺资源。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .pwm import analyze_channel, ChannelFinding
from .coincidence import cross_domain, match_log_prefix
from .attribution import attribute

SEVERITY_ORDER = {"CONFIRMED": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

# 良性剖面的特征：周期无规则 + 占空比恒定，或者与 CPU 负载强相关
BENIGN_PROFILE_FLAGS = {"load_noise", "static_oscillation", "flat"}


@dataclass
class Alert:
    severity: str
    title: str
    devices: list
    score: float
    evidence: dict
    writer: dict = field(default_factory=dict)
    suppression: str = ""
    count: int = 1

    def key(self):
        return (self.severity, tuple(sorted(self.devices)), self.title)

    def to_dict(self):
        return {
            "severity": self.severity,
            "title": self.title,
            "devices": list(self.devices),
            "score": round(self.score, 4),
            "evidence": self.evidence,
            "writer": self.writer,
            "suppression": self.suppression,
            "count": self.count,
        }


def _is_benign(f: ChannelFinding):
    """通道本身像正常机电负载（无稳定时钟 + 占空比恒定）。"""
    if f.aliased:
        return False
    if "clocked_duty_modulation" in f.flags:
        return False
    if set(f.flags) & BENIGN_PROFILE_FLAGS:
        return True
    if f.period_cv >= 0.25 and f.duty_cv <= 0.12:
        return True
    return False


def _dedup(alerts):
    """同窗口去重：同 key 只留一条并累加 count，保留最高分那条。"""
    out = {}
    for a in alerts:
        k = a.key()
        if k in out:
            out[k].count += 1
            if a.score > out[k].score:
                out[k].score = a.score
        else:
            out[k] = a
    return sorted(out.values(), key=lambda x: (-SEVERITY_ORDER[x.severity], -x.score))


def analyze_scenario(name, host_channels, phys_channels, pwm_writes=None,
                     log_blocks=None, learn_benign=True):
    """
    host_channels / phys_channels: {name: {"domain": str, "device": str,
                                             "times": [...], "values": [...]}}
    pwm_writes: {device: [PwmWrite,...]}
    log_blocks: [{"pid","process","data": bytes}]  可疑进程写出的数据块
    """
    host = {}
    for cname, spec in host_channels.items():
        host[cname] = analyze_channel(cname, spec.get("domain", "host"),
                                      spec["times"], spec["values"])
    phys = {}
    for cname, spec in phys_channels.items():
        phys[cname] = analyze_channel(cname, spec.get("domain", "physical"),
                                      spec["times"], spec["values"])

    alerts = []

    # ---- 1) 物理确认：主机通道 × 物理通道 ----
    for hn, hf in host.items():
        for pn, pf in phys.items():
            v = cross_domain(hf, pf)
            if v.tier in ("CONFIRMED", "HIGH"):
                writer_conf = 0.0
                writer_info = {}
                dev = host_channels[hn].get("device", hn)
                if pwm_writes and dev in pwm_writes:
                    at = attribute(dev, pwm_writes[dev])
                    writer_conf = at.confidence
                    writer_info = at.to_dict()
                sev = v.tier
                # 无写入者归因 → 降一级（可能是内核态操纵，需人工）
                if not writer_info and sev == "HIGH":
                    sev = "MEDIUM"
                alerts.append(Alert(
                    severity=sev,
                    title=f"物理外传疑似: {hn} 与 {pn} 同步调制",
                    devices=[dev, phys_channels[pn].get("device", pn)],
                    score=v.score,
                    evidence={"cross_domain": v.to_dict(),
                              "host_channel": hf.to_dict(),
                              "phys_channel": pf.to_dict()},
                    writer=writer_info,
                ))
            elif v.tier == "MEDIUM":
                alerts.append(Alert(
                    severity="MEDIUM",
                    title=f"单域异常调制: {hn}",
                    devices=[host_channels[hn].get("device", hn)],
                    score=hf.score,
                    evidence={"host_channel": hf.to_dict()},
                ))

    # ---- 2) 只有主机侧、无物理佐证 ----
    covered = set()
    for a in alerts:
        covered.update(a.devices)
    for hn, hf in host.items():
        dev = host_channels[hn].get("device", hn)
        if dev in covered:
            continue
        benign = learn_benign and _is_benign(hf)
        if hf.score >= 0.55 and not benign:
            writer_info = {}
            if pwm_writes and dev in pwm_writes:
                writer_info = attribute(dev, pwm_writes[dev]).to_dict()
            alerts.append(Alert(
                severity="MEDIUM" if writer_info else "LOW",
                title=f"执行器驱动异常(无物理佐证): {hn}",
                devices=[dev],
                score=hf.score,
                evidence={"host_channel": hf.to_dict()},
                writer=writer_info,
            ))
        elif hf.score >= 0.55 and benign:
            alerts.append(Alert(
                severity="INFO",
                title=f"良性剖面(已抑制): {hn}",
                devices=[dev],
                score=hf.score,
                evidence={"host_channel": hf.to_dict()},
                suppression="benign_profile",
            ))
        elif hf.score >= 0.30 and not benign:
            # 兜底：证据不足以进值班队列，但结构上明显不像正常负载
            # （典型如攻击者加了时基抖动）。必须留痕进日报，
            # 否则"对抗性降级"会变成完全静默 —— 那是最危险的漏报。
            alerts.append(Alert(
                severity="LOW",
                title=f"弱异常调制(需关注): {hn}",
                devices=[dev],
                score=hf.score,
                evidence={"host_channel": hf.to_dict()},
                suppression="",
            ))

    # ---- 3) 内容级确认：解调比特 vs 进程导出数据 ----
    if log_blocks:
        from .pwm import extract_bits
        for hn, hf in list(host.items()) + list(phys.items()):
            hits = match_log_prefix(extract_bits(hf), log_blocks)
            if hits:
                for h in hits:
                    alerts.append(Alert(
                        severity="CONFIRMED",
                        title=f"内容级确认: {hn} 传出进程数据",
                        devices=[hn],
                        score=0.95,
                        evidence={"content_match": h,
                                  "channel": hf.to_dict()},
                        writer={"process": h.get("process"),
                                "pid": h.get("pid")},
                    ))

    alerts = _dedup(alerts)
    return {
        "scenario": name,
        "host_channels": {k: v.to_dict() for k, v in host.items()},
        "phys_channels": {k: v.to_dict() for k, v in phys.items()},
        "alerts": [a.to_dict() for a in alerts],
        "paged": [a.to_dict() for a in alerts
                  if a.severity in ("CONFIRMED", "HIGH")],
        "daily": [a.to_dict() for a in alerts if a.severity == "MEDIUM"],
        "suppressed": [a.to_dict() for a in alerts if a.severity == "INFO"],
        "low": [a.to_dict() for a in alerts if a.severity == "LOW"],
    }
