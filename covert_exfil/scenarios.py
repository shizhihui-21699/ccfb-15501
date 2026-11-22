"""
场景合成器 —— 用于验证判据，而不是用来"造数据糊弄演示"。

这里刻意包含三类样本：
  A. 真实隐蔽信道（稳定符号时钟 + 变化占空比 + 跨域同相）
  B. 良性高负载（编译满载、热控爬升——它们同样让风扇狂转、功耗抖动）
  C. 对抗性反例（攻击者加随机抖动、只驱动单域、写 PWM 但机器没响应）

B 是压误报的考验，C 是压漏报的考验。两者都不通过，方案就没有工程价值。
"""
from __future__ import annotations

import math
import random


def _ts(n, dt):
    return [i * dt for i in range(n)]


def _bitstream(nbits, seed, mode="random"):
    rng = random.Random(seed)
    if mode == "ascii":
        payload = (b"TOP-SECRET-ARCHIVE-2026-Q4//project_owl//keyslot-"
                   b"7//exfil-test-vector/")
        bits = [(byte >> (7 - k)) & 1 for byte in payload for k in range(8)]
        return (bits * (nbits // len(bits) + 1))[:nbits]
    return [rng.getrandbits(1) for _ in range(nbits)]


def fan_secret_channel(n_symbols=64, T=0.020, dt=0.0005, seed=7, jitter=0.0):
    """
    隐蔽信道：周期 T 稳定，duty ∈ {0.35, 0.65} 编码比特。
    jitter 用于模拟攻击者加入的随机时基抖动（对抗检测）。
    """
    rng = random.Random(seed)
    bits = _bitstream(n_symbols, seed, "ascii")
    times, values = [], []
    t = 0.0
    for b in bits:
        Tj = T * (1.0 + jitter * rng.uniform(-1, 1))
        duty = 0.65 if b else 0.35
        n_hi = max(1, int(Tj * duty / dt))
        n_lo = max(1, int(Tj * (1 - duty) / dt))
        for _ in range(n_hi):
            times.append(t); values.append(1.0 + rng.gauss(0, 0.02)); t += dt
        for _ in range(n_lo):
            times.append(t); values.append(0.0 + rng.gauss(0, 0.02)); t += dt
    return times, values, bits


def led_secret_channel(n_symbols=64, T=0.021, dt=0.0005, seed=7, jitter=0.0):
    """同一比特流，通过硬盘指示灯发出——物理上独立于风扇的域。"""
    return fan_secret_channel(n_symbols, T * 1.05, dt, seed, jitter)


def phys_mic_of_secret(n_symbols=64, T=0.020, dt=0.0005, seed=7, snr=6.0):
    """带外麦克风"听到"的风扇声。含噪声、有延迟、增益不同（所以幅度不同）。"""
    times, values, bits = fan_secret_channel(n_symbols, T, dt, seed)
    rng = random.Random(seed + 999)
    delay = 0.0015
    out_t, out_v = [], []
    for i, (t, v) in enumerate(zip(times, values)):
        j = i - int(delay / dt)
        base = values[j] if 0 <= j < len(values) else v
        out_t.append(t)
        out_v.append(0.4 * base + 0.30 + rng.gauss(0, 0.4 / snr))
    return out_t, out_v, bits


def benign_compile_load(n=6000, dt=0.0005, seed=11):
    """编译满载：CPU 占用在 0-1 间随机切换、周期不固定 → 风扇转速抖、周期乱。"""
    rng = random.Random(seed)
    times = _ts(n, dt)
    values = []
    v = 0.2
    for _ in range(n):
        v += rng.gauss(0, 0.06)
        if rng.random() < 0.04:  # 偶发大跳变，像任务切换
            v += rng.uniform(-0.5, 0.5)
        v = max(0.0, min(1.0, v))
        values.append(v)
    return times, values


def benign_thermal_ramp(n=6000, dt=0.0005, seed=13):
    """热控爬升：温度驱动的慢速单调上升，占空比缓慢增大——有趋势但没有符号时钟。"""
    times = _ts(n, dt)
    values = []
    for i, t in enumerate(times):
        base = 0.15 + 0.6 * (t / (n * dt))
        wobble = 0.02 * math.sin(2 * math.pi * 0.5 * t)
        values.append(max(0.0, min(1.0, base + wobble)))
    return times, values


def benign_thermal_oscillation(n=6000, dt=0.0005, seed=17):
    """
    热控"寻的"振荡：周期稳定但占空比恒定 —— 这是最容易被误判的一种。
    它恰恰是要被 'regular but not varying → static_oscillation' 排除的。
    """
    times = _ts(n, dt)
    values = []
    for t in times:
        ph = (t % 0.25) / 0.25
        values.append(1.0 if ph < 0.5 else 0.0)
    return times, values


def attack_jittered(n_symbols=64, T=0.020, dt=0.0005, seed=23):
    """对抗：加 25% 随机时基抖动，试图破坏"稳定时钟"判据。"""
    return fan_secret_channel(n_symbols, T, dt, seed, jitter=0.25)


def attack_single_domain(n_symbols=64, dt=0.0005, seed=29):
    """对抗：只驱动风扇、指示灯不动 —— 跨域应判不出 CONFIRMED。"""
    t, v, bits = fan_secret_channel(n_symbols, 0.020, dt, seed)
    bt, bv = benign_thermal_ramp(len(t), dt, seed)
    return t, v, bits, bt, bv


def attack_pwm_no_physical(n_symbols=64, dt=0.0005, seed=31):
    """
    对抗：软件在疯狂写 PWM，但执行器没真动（被固件限速/虚拟化环境）。
    主机侧高分、物理侧平坦 → 不应升级为外传告警。
    """
    t, v, bits = fan_secret_channel(n_symbols, 0.020, dt, seed)
    pt, pv = benign_thermal_ramp(len(t), dt, seed + 1)
    return t, v, pt, pv
