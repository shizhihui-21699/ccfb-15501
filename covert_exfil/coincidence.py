"""
跨域符合性（coincidence）—— 压掉误报的第二道闸，也是"确认"的唯一来源。

物理常识
--------
真正的物理外传必须让**某个物理场真的发生变化**。而软件侧看到的"写 PWM"
只是指令，不保证执行器真的按它动。所以：

  * 只有执行器通道（风扇/指示灯）的分高，可能是软件在狂写 PWM 但机器没响应，
    也可能只是某驱动在测试——不构成外传证据。
  * 只有物理场（声音/功耗/光）的分高，可能是人在旁边打电话、空调启停——
    同样不构成证据。
  * 两个**物理上互相独立**的域，在同一时刻、同一符号速率下同时调制，
    才是隐蔽信道的signature。攻击者要伪造就必须真的把两个执行器都驱动起来，
    那反而更容易被房间里的传感器抓到。

跨域"符合"的四条独立证据（任意两条强证据即升级）：
  1. 符号速率一致（|Δrate|/rate 小）
  2. 调制包络相关（两通道的占空比/幅值序列对齐后相关）
  3. 包络的起始/结束时刻重合（同时开、同时停）
  4. 内容级比对（若能解出比特，与某进程的导出数据前缀逐比特匹配）

注意：这里刻意改用 **Pearson 相关**而不是"占比一致"这类朴素算法——
朴素算法对幅度缩放和偏置极其敏感，同一个信道只要增益不同就会漏配或错配。
"""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field

from .pwm import ChannelFinding, extract_bits


def _pearson(a, b):
    n = min(len(a), len(b))
    if n < 3:
        return 0.0
    a, b = a[:n], b[:n]
    ma = sum(a) / n
    mb = sum(b) / n
    num = sum((x - ma) * (y - mb) for x, y in zip(a, b))
    da = math.sqrt(sum((x - ma) ** 2 for x in a))
    db = math.sqrt(sum((y - mb) ** 2 for y in b))
    if da <= 0 or db <= 0:
        return 0.0
    return num / (da * db)


def _resample(series, t0, dt, n):
    """把 (time, value) 序列线性重采样到统一网格，便于相关分析。"""
    if not series or dt <= 0:
        return []
    out = []
    j = 0
    for i in range(n):
        t = t0 + i * dt
        while j + 1 < len(series) and series[j + 1][0] <= t:
            j += 1
        if j + 1 >= len(series):
            out.append(series[-1][1])
            continue
        (ta, va), (tb, vb) = series[j], series[j + 1]
        if tb == ta:
            out.append(va)
        else:
            f = (t - ta) / (tb - ta)
            f = 0.0 if f < 0 else 1.0 if f > 1 else f
            out.append(va + f * (vb - va))
    return out


def rate_agreement(rate_a, rate_b):
    """符号速率一致度 ∈ [0,1]。"""
    if rate_a <= 0 or rate_b <= 0:
        return 0.0
    r = abs(rate_a - rate_b) / max(rate_a, rate_b)
    return max(0.0, 1.0 - r / 0.25)  # 25% 以内线性衰减到 0


def envelope_correlation(fa: ChannelFinding, fb: ChannelFinding):
    """
    两通道调制包络的相关。先在各自符号格点上重采样到较慢的那个速率上。
    返回 (corr, phase_shift_symbols)。
    """
    if not fa.mod_series or not fb.mod_series:
        return 0.0, 0
    ra = fa.symbol_rate
    rb = fb.symbol_rate
    if ra <= 0 or rb <= 0:
        return 0.0, 0
    slower = min(ra, rb)
    dt = 1.0 / slower
    t0 = max(fa.mod_series[0][0], fb.mod_series[0][0])
    t1 = min(fa.mod_series[-1][0], fb.mod_series[-1][0])
    if t1 <= t0:
        return 0.0, 0
    n = int((t1 - t0) / dt) + 1
    if n < 4:
        return 0.0, 0
    A = _resample(fa.mod_series, t0, dt, n)
    B = _resample(fb.mod_series, t0, dt, n)
    corr = _pearson(A, B)
    # 检查 ±2 个符号的相位偏移，取最大相关，避免因采样错位漏判
    best, best_shift = corr, 0
    for shift in (-2, -1, 1, 2):
        if 0 <= shift:
            a, b = A[shift:], B[:len(B) - shift] if shift else B
        else:
            a, b = A[:len(A) + shift], B[-shift:]
        c = _pearson(a, b)
        if c > best:
            best, best_shift = c, shift
    return best, best_shift


def timing_overlap(fa: ChannelFinding, fb: ChannelFinding):
    """
    两通道调制活动窗口的重合度（Jaccard 风格）。
    真正的同步外传，两个执行器应当几乎同时开始、同时停止。
    """
    if not fa.mod_series or not fb.mod_series:
        return 0.0
    a0, a1 = fa.mod_series[0][0], fa.mod_series[-1][0]
    b0, b1 = fb.mod_series[0][0], fb.mod_series[-1][0]
    inter = max(0.0, min(a1, b1) - max(a0, b0))
    union = max(a1, b1) - min(a0, b0)
    return inter / union if union > 0 else 0.0


def content_match(fa: ChannelFinding, fb: ChannelFinding, min_bits=16):
    """
    内容级比对：分别解调出比特，检查是否逐比特一致（可容忍少量误码）。
    这是最强证据——它把"两个通道都在调制"升级为"两个通道在传同一串数据"。
    """
    ba = extract_bits(fa)
    bb = extract_bits(fb)
    k = min(len(ba), len(bb))
    if k * 8 < min_bits:
        return 0.0, 0
    a, b = ba[:k], bb[:k]
    diff = sum(bin(x ^ y).count("1") for x, y in zip(a, b))
    total = k * 8
    ber = diff / total
    agreement = max(0.0, 1.0 - ber / 0.20)  # 20% 误码以内仍认为同源
    return agreement, total


@dataclass
class CrossDomainVerdict:
    pair: str
    independent_domains: bool
    rate: float
    rate_agree: float
    env_corr: float
    phase_shift: int
    overlap: float
    ber_agreement: float
    compared_bits: int
    score: float
    tier: str
    reasons: list = field(default_factory=list)

    def to_dict(self):
        return {
            "pair": self.pair,
            "independent_domains": self.independent_domains,
            "symbol_rate_sps": round(self.rate, 3),
            "rate_agreement": round(self.rate_agree, 3),
            "envelope_corr": round(self.env_corr, 3),
            "phase_shift_symbols": self.phase_shift,
            "timing_overlap": round(self.overlap, 3),
            "bit_agreement": round(self.ber_agreement, 3),
            "compared_bits": self.compared_bits,
            "score": round(self.score, 4),
            "tier": self.tier,
            "reasons": list(self.reasons),
        }


def cross_domain(fa: ChannelFinding, fb: ChannelFinding,
                 weak_score_floor=0.30):
    """
    两个通道的跨域判定。返回 CrossDomainVerdict。
    score 只有在两域物理独立时才被允许拉高——同域（比如两个风扇）只能证明
    "多处一致"，攻击者可以轻易同域复制，所以同域最高只到 MEDIUM。
    """
    same_domain = fa.domain == fb.domain
    line = f"{fa.name}<->{fb.name}"

    if fa.score < weak_score_floor and fb.score < weak_score_floor:
        return CrossDomainVerdict(line, not same_domain, 0.0, 0.0, 0.0, 0, 0.0,
                                  0.0, 0, 0.0, "NONE",
                                  ["neither_channel_reaches_floor"])

    rate = 0.5 * (fa.symbol_rate + fb.symbol_rate)
    ra = rate_agreement(fa.symbol_rate, fb.symbol_rate)
    corr, shift = envelope_correlation(fa, fb)
    ov = timing_overlap(fa, fb)
    ber_agree, bits = content_match(fa, fb)

    reasons = []
    strong = 0
    if ra >= 0.8:
        strong += 1
        reasons.append("symbol_rate_matched")
    if corr >= 0.6:
        strong += 1
        reasons.append("envelope_correlated")
    if ov >= 0.6:
        strong += 1
        reasons.append("timing_overlapped")
    if ber_agree >= 0.8 and bits >= 16:
        strong += 1
        reasons.append("bit_content_matched")

    base = 0.5 * (fa.score + fb.score)
    score = base * (0.55 * min(1.0, strong / 3.0) + 0.25 * ra + 0.20 * corr)
    if bits >= 16 and ber_agree >= 0.8:
        score = max(score, 0.90)  # 内容级匹配直接封顶确认
    if ov >= 0.6:
        score += 0.05
    score = max(0.0, min(1.0, score))

    if same_domain:
        reasons.append("same_domain_not_independent")
        score = min(score, 0.45)

    if not same_domain and score >= 0.80 and strong >= 2:
        tier = "CONFIRMED"
    elif not same_domain and score >= 0.55 and strong >= 1:
        tier = "HIGH"
    elif score >= 0.30:
        tier = "MEDIUM"
    else:
        tier = "LOW"

    return CrossDomainVerdict(line, not same_domain, rate, ra, corr, shift, ov,
                              ber_agree, bits, score, tier, reasons)


def fingerprint(data: bytes) -> str:
    """用于与"外传日志"做内容溯源：比对的是数据指纹，不是全文，避免泄露内容。"""
    return hashlib.blake2b(data, digest_size=16).hexdigest()


def match_log_prefix(bits: bytes, log_blocks, min_overlap=16):
    """
    把解调得到的比特流，与可疑进程写出的数据块做前缀匹配。
    命中即内容级确认（比统计相关强得多）。
    """
    if not bits:
        return None
    hits = []
    nbits = len(bits) * 8
    for blk in log_blocks:
        data = blk.get("data", b"")
        if not data:
            continue
        cand = data[:len(bits)]
        k = min(len(cand), len(bits))
        if k * 8 < min_overlap:
            continue
        a, b = bits[:k], cand[:k]
        diff = sum(bin(x ^ y).count("1") for x, y in zip(a, b))
        ber = diff / (k * 8)
        if ber <= 0.20:
            hits.append({
                "pid": blk.get("pid"),
                "process": blk.get("process"),
                "offset": 0,
                "bits_compared": k * 8,
                "ber": round(ber, 4),
                "digest_prefix": fingerprint(cand),
            })
    return hits or None
