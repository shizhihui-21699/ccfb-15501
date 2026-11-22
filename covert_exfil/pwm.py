"""
PWM / 载波-占空比调制检测（物理侧信道的第一性判据）

设计前提
--------
正常机电负载变化的特征是：幅值/转速漂移，周期抖动大，占空比恒定或随机。
隐蔽物理信道（风扇声、指示灯闪、功耗抖动）的共同结构是：

    存在一个稳定的"符号时钟" T（周期几乎不变），
    而信息编码在占空比 duty = t_high / T 上，duty 随比特变化。

因此核心判别式是 **稳定周期 + 变化占空比**，而不是"值变了"。
这条判据把"满载编译导致风扇狂转"这类常见误报直接排除：
那种情况下 duty 基本恒定，或者周期完全无规律。

本模块只做单通道的"行为学"判定，不负责证明数据真的出去了。
物理确认必须靠跨域符合性（见 coincidence.py），这是刻意设计的责任分离：
单通道高分 ≠ 有数据外传，只等于"该执行器的驱动方式异常"。
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

# 隐蔽信道常用的符号周期范围（下界是机械/人眼分辨率，上界覆盖"极慢外传"）
PREDATORY_PERIOD_S = (0.5e-3, 5.0)
# 执行器能承载的符号速率上限。指示灯(LED)可以很快，风扇受机械惯性限制，
# 这里取覆盖两者的宽松上界；超过它才降权。
MAX_PLAUSIBLE_SYMBOL_RATE = 100.0


# ---------------------------------------------------------------- 基础统计

def _median(xs):
    s = sorted(xs)
    n = len(s)
    if n == 0:
        return 0.0
    return s[n // 2] if n % 2 else 0.5 * (s[n // 2 - 1] + s[n // 2])


def robust_scale(xs):
    """MAD 归一化的稳健标准差；MAD 退化时回退到普通标准差。"""
    n = len(xs)
    if n == 0:
        return 0.0
    med = _median(xs)
    mad = _median([abs(v - med) for v in xs])
    if mad > 0:
        return 1.4826 * mad
    m = sum(xs) / n
    return math.sqrt(sum((v - m) ** 2 for v in xs) / n)


def _cv(xs):
    """变异系数。用于衡量"周期是否像时钟"和"占空比是否在变"。"""
    n = len(xs)
    if n < 2:
        return 0.0
    m = sum(xs) / n
    if m == 0:
        return 0.0
    return math.sqrt(sum((v - m) ** 2 for v in xs) / (n - 1)) / abs(m)


def _winsorize(xs, k=4.0):
    med = _median(xs)
    sc = robust_scale(xs)
    if sc <= 0:
        return list(xs)
    lo, hi = med - k * sc, med + k * sc
    return [lo if v < lo else hi if v > hi else v for v in xs]


def _rolling_mean(xs, half):
    """前缀和实现的 O(n) 滑窗均值，用于剥掉慢速负载趋势。"""
    n = len(xs)
    pre = [0.0] * (n + 1)
    for i, v in enumerate(xs):
        pre[i + 1] = pre[i] + v
    out = [0.0] * n
    for i in range(n):
        a = i - half
        b = i + half + 1
        if a < 0:
            a = 0
        if b > n:
            b = n
        out[i] = (pre[b] - pre[a]) / (b - a)
    return out


def _cross_time(t0, y0, t1, y1, level=0.0):
    if y1 == y0:
        return t1
    f = (level - y0) / (y1 - y0)
    f = 0.0 if f < 0 else 1.0 if f > 1 else f
    return t0 + f * (t1 - t0)


# ---------------------------------------------------------------- 边沿与周期

def _hysteresis_edges(times, r, refractory=0.0):
    """
    带滞回的过零检测，返回 [(time, direction)]，direction +1=上升。

    用滞回而不是单阈值，是为了避免噪声在阈值附近反复穿越产生假边沿。
    refractory（最小边沿间距）用来吞掉记录起止处的瞬态伪边沿——
    去趋势残余在两端天然不归零，会产生一个几乎贴着实边沿的假跳变，
    它会严重污染首/末符号的周期与占空比估计。这是实测中最常见的偏差源。
    """
    hi, lo = 0.5, -0.5
    edges = []
    state = None  # None=未定, 1=高, 0=低
    for i in range(len(r)):
        v = r[i]
        if state is None:
            if v > hi:
                state = 1
                edges.append((times[i], 1))
            elif v < lo:
                state = 0
                edges.append((times[i], -1))
            continue
        if state == 1 and v < lo:
            cand = _cross_time(times[i - 1], r[i - 1], times[i], v, 0.0)
            if not edges or cand - edges[-1][0] >= refractory:
                edges.append((cand, -1))
                state = 0
            # 在 refractory 内的翻转直接忽略，保持 state 不变，等待真正的边沿
        elif state == 0 and v > hi:
            cand = _cross_time(times[i - 1], r[i - 1], times[i], v, 0.0)
            if not edges or cand - edges[-1][0] >= refractory:
                edges.append((cand, 1))
                state = 1
    return edges


def _intervals(edges):
    """相邻异向边沿之间的时长，按"该段是 HIGH 还是 LOW"归类。"""
    highs, lows = [], []
    for k in range(len(edges) - 1):
        (t0, d0), (t1, d1) = edges[k], edges[k + 1]
        if d0 == d1:
            continue  # 同向边沿说明中间被丢掉了，跳过
        dur = t1 - t0
        if dur <= 0:
            continue
        if d0 == 1:
            highs.append((t0, dur))
        else:
            lows.append((t0, dur))
    return highs, lows


def _score(period_cv, duty_cv, duty_mean, t_mean, n_periods, n_levels,
           aliased, median_dt):
    """
    组合打分。核心是两条连续轴相乘（"与"关系），不是加权求和：

        R = 周期有多规则   = 1 - period_cv / 0.30
        D = 占空比变化多深 = (duty_cv - 0.06) / 0.26

        base = R * D

    相乘保证了"周期规则但占空比恒定"（静态振荡，D≈0）和
    "占空比乱跳但周期无规律"（正常负载，R≈0）都拿不到分。
    连续化（而不是在 period_cv=0.10/0.22 处硬跳崖）是为了让
    "攻击者加了时基抖动"这类中间情形平滑降级，而不是突然沉默——
    它会掉到日报级，而不是掉进黑洞。这正是不漏报的兜底。

    D 的分母取 0.26：一个可靠的平衡二电平信道（占空比 0.35/0.65）
    其 duty_cv≈0.30，应当拿到接近满分的 D。若分母过大，
    最经典的隐蔽信道反而拿不到高分 —— 这是标定错误，不是攻击者厉害。
    """
    R = max(0.0, min(1.0, 1.0 - period_cv / 0.30))
    D = max(0.0, min(1.0, (duty_cv - 0.06) / 0.26))
    base = R * D

    flags = []
    if period_cv < 0.10 and duty_cv > 0.12:
        flags.append("clocked_duty_modulation")
    elif period_cv < 0.25 and duty_cv > 0.12:
        flags.append("semi_periodic_duty")
    elif period_cv < 0.10:
        flags.append("static_oscillation")
    elif duty_cv <= 0.06:
        flags.append("flat")
    else:
        flags.append("load_noise")

    score = 0.85 * base

    # 以下加分只在核心证据达到最低可信度时才生效，
    # 否则编译满载的"9 个离散电平"之类噪声特征会给它刷分。
    if base >= 0.15:
        if PREDATORY_PERIOD_S[0] <= t_mean <= PREDATORY_PERIOD_S[1]:
            score += 0.07
            flags.append("predatory_period")
        else:
            flags.append("period_outside_predatory")
        if 2 <= n_levels <= 12:
            score += 0.06
            flags.append("discrete_symbol_levels")
        else:
            flags.append("continuous_duty")
        if 0.02 < duty_mean < 0.98:
            score += 0.02
            flags.append("meaningful_duty")
        else:
            flags.append("rail_duty")
    else:
        flags.append("below_core_floor")

    # 符号速率在机械上是否可能
    if t_mean > 0 and 1.0 / t_mean > MAX_PLAUSIBLE_SYMBOL_RATE:
        score *= 0.5
        flags.append("implausible_symbol_rate")

    # 采样率不足会发生混叠，此时结论不可信，降权并标注
    if aliased:
        score *= 0.5
        flags.append("undersampled_aliasing")

    # 观测到的周期数太少，结论不稳健
    if n_periods < 6:
        score *= max(0.35, min(1.0, (n_periods - 1) / 5.0))
        flags.append("few_periods")

    return max(0.0, min(1.0, score)), flags


# ---------------------------------------------------------------- 超长周期

def _plateau(times, xs):
    """
    当符号周期长于整个记录窗口时（极慢外传），周期检测看不见。
    此时退化为"长时间恒定平台"检测：一段持续的、非趋势的、恒定偏移。
    这类证据只给弱分，必须靠跨域符合性才能升级。
    """
    n = len(xs)
    if n < 20:
        return False, 0.0
    med = _median(xs)
    sc = robust_scale(xs) or 1.0
    z = [(v - med) / sc for v in xs]
    best_len = 0
    i = 0
    while i < n:
        if abs(z[i]) < 2.0:
            i += 1
            continue
        j = i
        while j < n and abs(z[j]) >= 2.0:
            j += 1
        seg = xs[i:j]
        seg_cv = _cv(seg)
        dur = times[j - 1] - times[i] if j - 1 > i else 0.0
        if seg_cv < 0.08 and dur >= 5.0:
            best_len = max(best_len, dur)
        i = j
    return best_len > 0, best_len


# ---------------------------------------------------------------- 结论结构

@dataclass
class ChannelFinding:
    name: str
    domain: str
    score: float
    flags: list
    period_s: float = 0.0
    duty_mean: float = 0.0
    duty_cv: float = 0.0
    period_cv: float = 0.0
    symbol_rate: float = 0.0
    n_periods: int = 0
    n_levels: int = 0
    aliased: bool = False
    plateau: bool = False
    plateau_s: float = 0.0
    # 每个符号一个样本：(周期中点, 占空比)，供跨域符合性使用
    mod_series: list = field(default_factory=list)
    duty_series: list = field(default_factory=list)

    def to_dict(self):
        return {
            "name": self.name,
            "domain": self.domain,
            "score": round(self.score, 4),
            "flags": list(self.flags),
            "period_ms": round(self.period_s * 1000, 3),
            "duty_mean": round(self.duty_mean, 4),
            "duty_cv": round(self.duty_cv, 4),
            "period_cv": round(self.period_cv, 4),
            "symbol_rate_sps": round(self.symbol_rate, 3),
            "n_periods": self.n_periods,
            "n_levels": self.n_levels,
            "aliased": self.aliased,
            "plateau": self.plateau,
            "plateau_s": round(self.plateau_s, 3),
        }


def analyze_channel(name, domain, times, values, min_periods=3):
    """
    对单个执行器/传感器通道做"是否在使用 PWM 符号时钟"的判定。

    多尺度策略：在若干去趋势宽度上都试一次，取最优。因为符号周期未知，
    去趋势窗口必须明显大于一个符号周期，否则会把载波本身当趋势剥掉。
    """
    n = len(times)
    if n < 12:
        return ChannelFinding(name, domain, 0.0, ["insufficient_data"])

    dts = [times[i + 1] - times[i] for i in range(n - 1) if times[i + 1] > times[i]]
    if not dts:
        return ChannelFinding(name, domain, 0.0, ["no_time_axis"])
    median_dt = _median(dts)

    xs = _winsorize(list(values))
    base_sc = robust_scale(xs)
    if base_sc <= 0:
        return ChannelFinding(name, domain, 0.0, ["constant_signal"])

    widths = [w for w in (max(5, n // 32), max(5, n // 16), max(5, n // 8),
                          max(5, n // 4), max(5, n // 2)) if w >= 3]
    cands = []

    for half in sorted(set(widths)):
        resid = [xs[i] - m for i, m in enumerate(_rolling_mean(xs, half))]
        sc = robust_scale(resid)
        if sc <= 0:
            continue
        r = [v / sc for v in resid]
        edges = _hysteresis_edges(times, r, refractory=0.6 * median_dt)
        if len(edges) < 2 * min_periods + 1:
            continue
        highs, lows = _intervals(edges)
        k = min(len(highs), len(lows))
        if k < min_periods:
            continue

        periods, duties, mod = [], [], []
        for i in range(k):
            t_h, d_h = highs[i]
            _, d_l = lows[i]
            T = d_h + d_l
            if T <= 0:
                continue
            periods.append(T)
            duties.append(d_h / T)
            mod.append((t_h + T / 2.0, d_h / T))
        if len(periods) < min_periods:
            continue

        t_mean = sum(periods) / len(periods)
        cands.append({
            "half": half, "t_mean": t_mean, "periods": periods,
            "duties": duties, "mod": mod,
        })

    best = None
    if cands:
        # 第一遍：用最宽的（最小的）去趋势窗口粗估周期 T_ref。
        # 窄窗口会把载波本身当作趋势剥掉，产生伪造的"周期"，必须先排除这种窗口。
        ref = min(cands, key=lambda c: c["t_mean"])
        t_ref = ref["t_mean"]
        # 第二遍：只保留"窗口半宽 ≥ 一个符号周期"的候选，它们不会削掉载波。
        usable = [c for c in cands if c["half"] * median_dt >= 1.2 * t_ref]
        if not usable:
            usable = cands
        for c in usable:
            periods, duties = c["periods"], c["duties"]
            t_mean = c["t_mean"]
            p_cv = _cv(periods)
            d_cv = _cv(duties)
            d_mean = sum(duties) / len(duties)
            levels = len({round(v, 1) for v in duties})
            aliased = t_mean < 4.0 * median_dt
            score, flags = _score(p_cv, d_cv, d_mean, t_mean, len(periods),
                                  levels, aliased, median_dt)
            cand = (score, t_mean, p_cv, d_cv, d_mean, len(periods), levels,
                    aliased, flags, c["mod"], duties)
            if best is None or cand[0] > best[0]:
                best = cand

    plat, plat_s = _plateau(times, xs)

    if best is None:
        f = ChannelFinding(name, domain, 0.0, ["no_periodic_structure"])
        f.plateau, f.plateau_s = plat, plat_s
        if plat:
            f.score = 0.22
            f.flags = ["long_plateau_only"]
        return f

    score, t_mean, p_cv, d_cv, d_mean, nper, levels, aliased, flags, mod, duties = best
    f = ChannelFinding(
        name=name, domain=domain, score=score, flags=flags,
        period_s=t_mean, duty_mean=d_mean, duty_cv=d_cv, period_cv=p_cv,
        symbol_rate=(1.0 / t_mean if t_mean > 0 else 0.0),
        n_periods=nper, n_levels=levels, aliased=aliased,
        plateau=plat, plateau_s=plat_s, mod_series=mod, duty_series=duties,
    )
    if plat and f.score < 0.5:
        f.flags = list(f.flags) + ["long_plateau"]
    return f


def extract_bits(finding, threshold=None):
    """
    把占空比序列转成比特流（用于和"外传日志"做内容级比对，而不是只比统计特征）。
    这是把"疑似"升级为"确认"的最强手段：如果解出的比特与某进程导出的
    数据前缀在比特级上匹配，就不需要任何概率论证。
    """
    d = finding.duty_series
    if not d:
        return b""
    thr = 0.5 if threshold is None else threshold
    bits = [1 if v >= thr else 0 for v in d]
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)
