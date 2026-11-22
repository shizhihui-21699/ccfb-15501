"""
执行链归因：把"某个执行器在异常调制"落到"哪个进程在驱动它"。

为什么这是必需的
----------------
物理侧只能告诉你"有信号"，无法告诉你是谁发的。而"谁在写 PWM"是主机内
唯一可靠、低成本、且能直接产出可处置证据（PID、进程名、命令行、哈希）的信号。
两者结合，安全员拿到的才是"可行动的告警"而不是"房间里有怪声"。

本模块只做纯算法部分：给定采样器输出的"跨进程 PWM 写入记录"，
计算归因置信度。真实采样器在 Linux 上走 tracefs / ftrace 的
pwm_apply_state 或 dev_pwm 事件（见 collectors/linux_pwm.py），
Windows 上走 ETW（框架预留接口）。

重要局限（必须写进运维手册）
--------------------------
若恶意程序运行在**内核态**（rootkit），它可以直接操纵寄存器而完全绕开
被 trace 的函数，此时归因会落空——这就是为什么必须有带外传感器。
归因模块的存在不改变这个结论，它只是让内核态以下的攻击变得很好抓。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class PwmWrite:
    ts: float
    pid: int
    process: str
    device: str        # 例如 "hwmon:pwm2" / "leds:input3"
    duty: float        # 0..1
    period_us: float   # 写入的 PWM 周期，微秒


@dataclass
class Attribution:
    device: str
    writer_pid: int
    writer_process: str
    distinct_writers: int
    write_rate_sps: float
    duty_variability: float
    confidence: float
    suspicious_writers: list = field(default_factory=list)
    reasons: list = field(default_factory=list)

    def to_dict(self):
        return {
            "device": self.device,
            "writer_pid": self.writer_pid,
            "writer_process": self.writer_process,
            "distinct_writers": self.distinct_writers,
            "write_rate_sps": round(self.write_rate_sps, 3),
            "duty_variability": round(self.duty_variability, 4),
            "confidence": round(self.confidence, 4),
            "suspicious_writers": list(self.suspicious_writers),
            "reasons": list(self.reasons),
        }


# 正常系统中可能合法写 PWM 的进程（用于降噪，不是白名单——白名单会被滥用）
BENIGN_WRITERS = {
    "systemd", "thermald", "fancontrol", "lm-sensors", "acpid",
    "upowerd", "power-profiles-daemon", "gpu-manager", "kworker",
}


def attribute(device, writes):
    """
    核心思想：正常用户态程序几乎不会高频、高变率地写同一个 PWM 设备。
    驱动风扇/指示灯的通常是固定周期的守护进程（写率恒定、占空比平缓）。
    符合"高频 + 占空比剧烈变化 + 单写入者"的组合，才是可疑的。
    """
    if not writes:
        return Attribution(device, -1, "", 0, 0.0, 0.0, 0.0,
                           reasons=["no_writes"])

    by_pid = defaultdict(list)
    for w in writes:
        by_pid[w.pid].append(w)

    t0, t1 = writes[0].ts, writes[-1].ts
    span = max(1e-6, t1 - t0)

    best = None
    for pid, ws in by_pid.items():
        ws.sort(key=lambda x: x.ts)
        rates = []
        for i in range(1, len(ws)):
            dt = ws[i].ts - ws[i - 1].ts
            if dt > 0:
                rates.append(1.0 / dt)
        rate = sum(rates) / len(rates) if rates else 0.0
        duties = [w.duty for w in ws]
        dmean = sum(duties) / len(duties)
        dvar = (sum((d - dmean) ** 2 for d in duties) / len(duties)) ** 0.5
        proc = ws[0].process

        conf = 0.0
        reasons = []
        if rate >= 1.0:
            conf += 0.35
            reasons.append("high_write_rate")
        if dvar >= 0.10:
            conf += 0.30
            reasons.append("duty_varies_sharply")
        if proc not in BENIGN_WRITERS:
            conf += 0.15
            reasons.append("non_daemon_writer")
        if len(ws) / span >= 0.5:
            conf += 0.10
            reasons.append("sustained_activity")

        cand = (conf, pid, proc, rate, dvar, reasons, len(ws) / span)
        if best is None or cand[0] > best[0]:
            best = cand

    conf, pid, proc, rate, dvar, reasons, _ = best
    sus = [f"{p.pid}:{p.process}" for p in writes
           if p.process not in BENIGN_WRITERS]
    sus = sorted(set(sus))
    if len(by_pid) > 3:
        reasons.append("many_writers_maybe_wrapped")

    return Attribution(device, pid, proc, len(by_pid), rate, dvar,
                       min(1.0, conf), sus, reasons)
