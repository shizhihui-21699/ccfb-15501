"""
误报压力测试 —— 这才是决定这套东西能不能上值班队列的指标。

方法：把良性负载模型（编译满载、热控爬升、寻的振荡、混合负载）
用几百个不同随机种子各跑一遍，统计：
  * 进值班队列（CONFIRMED/HIGH）的比例  ← 必须接近 0，否则安全员会被淹没
  * 进日报（MEDIUM）的比例
  * 完全沉默的比例
同时对攻击样本统计漏报率。两边的目标是不对称的：
值班队列宁可漏，不可滥；漏掉的必须被日报兜住。
"""
from __future__ import annotations

import random
import sys

from covert_exfil.pwm import analyze_channel
from covert_exfil.scenarios import (
    benign_compile_load, benign_thermal_ramp, benign_thermal_oscillation,
    fan_secret_channel, attack_jittered,
)


def _mixed_benign(n, dt, seed):
    """混合负载：一段爬升 + 一段满载 + 一段振荡，模拟真实主机的日常。"""
    rng = random.Random(seed)
    t = [i * dt for i in range(n)]
    v = []
    third = n // 3
    _, a = benign_thermal_ramp(third, dt, seed)
    _, b = benign_compile_load(third, dt, seed + 1)
    _, c = benign_thermal_oscillation(n - 2 * third, dt, seed + 2)
    v = a + b + c
    # 叠加测量噪声
    v = [max(0.0, min(1.0, x + rng.gauss(0, 0.02))) for x in v]
    return t, v


def run_fp(n_trials=300, seed0=1000):
    stats = {"PAGED": 0, "MEDIUM": 0, "LOW": 0, "SILENT": 0, "scores": []}
    worst = []
    for i in range(n_trials):
        s = seed0 + i
        kind = i % 4
        if kind == 0:
            t, v = benign_compile_load(6000, 0.0005, seed=s)
            name = "compile"
        elif kind == 1:
            t, v = benign_thermal_ramp(6000, 0.0005, seed=s)
            name = "ramp"
        elif kind == 2:
            t, v = benign_thermal_oscillation(4000, 0.0005, seed=s)
            name = "osc"
        else:
            t, v = _mixed_benign(6000, 0.0005, seed=s)
            name = "mixed"
        f = analyze_channel(name, "host", t, v)
        stats["scores"].append(f.score)
        if f.score >= 0.80:
            stats["PAGED"] += 1
            worst.append((f.score, name, s, f.flags))
        elif f.score >= 0.55:
            stats["MEDIUM"] += 1
            worst.append((f.score, name, s, f.flags))
        elif f.score >= 0.30:
            stats["LOW"] += 1
        else:
            stats["SILENT"] += 1
    return stats, worst


def run_fn(n_trials=200, seed0=5000):
    """
    攻击侧漏报。注意验收口径必须符合架构：

    单主机通道在物理上无法区分"真外传"和"某个进程在异常驱动执行器"，
    所以它最高只到 HIGH/日报；进值班队列(CONFIRMED)必须靠跨域确认。
    因此这里分别考核：
      * 单通道是否"被发现异常"（score>=0.55，即至少进日报/HIGH）
      * 对抗抖动是否至少留痕（score>=0.30，进 LOW，不沉默）
    跨域升级的考核见 demo.py。
    """
    res = {"secret_detected": 0, "secret_total": 0,
           "jitter_noted": 0, "jitter_total": 0,
           "secret_scores": [], "jitter_scores": []}
    for i in range(n_trials):
        s = seed0 + i
        T = 0.012 + 0.00002 * (i % 20)
        t, v, _ = fan_secret_channel(48, T, 0.0005, seed=s)
        f = analyze_channel("secret", "host", t, v)
        res["secret_total"] += 1
        res["secret_scores"].append(f.score)
        if f.score >= 0.55:
            res["secret_detected"] += 1

        tj, vj, _ = attack_jittered(48, T, 0.0005, seed=s)
        fj = analyze_channel("jitter", "host", tj, vj)
        res["jitter_total"] += 1
        res["jitter_scores"].append(fj.score)
        if fj.score >= 0.30:
            res["jitter_noted"] += 1
    return res


if __name__ == "__main__":
    stats, worst = run_fp(300)
    n = sum(stats[k] for k in ("PAGED", "MEDIUM", "LOW", "SILENT"))
    sc = sorted(stats["scores"])
    print("=== 良性负载误报（300 个随机样本）===")
    print(f"  进值班队列(PAGED) : {stats['PAGED']:3d}  ({100*stats['PAGED']/n:.1f}%)")
    print(f"  日报(MEDIUM)      : {stats['MEDIUM']:3d}  ({100*stats['MEDIUM']/n:.1f}%)")
    print(f"  存证(LOW)         : {stats['LOW']:3d}  ({100*stats['LOW']/n:.1f}%)")
    print(f"  沉默(SILENT)      : {stats['SILENT']:3d}  ({100*stats['SILENT']/n:.1f}%)")
    print(f"  分数中位数={sc[len(sc)//2]:.3f}  p95={sc[int(len(sc)*0.95)]:.3f}  max={sc[-1]:.3f}")
    if worst:
        print("  最高分的良性样本（必须人工复看这些是否真是良性）:")
        for w in sorted(worst, reverse=True)[:5]:
            print(f"    {w[0]:.3f} {w[1]} seed={w[2]} {w[3]}")

    res = run_fn(200)
    ss = sorted(res["secret_scores"])
    js = sorted(res["jitter_scores"])
    print("\n=== 攻击侧检出 ===")
    print(f"  真信道 被发现异常(>=0.55): {res['secret_detected']}/{res['secret_total']} "
          f"({100*res['secret_detected']/res['secret_total']:.1f}%)"
          f"  分数 min={ss[0]:.3f} p5={ss[int(len(ss)*0.05)]:.3f}")
    print(f"  对抗抖动 至少留痕(>=0.30): {res['jitter_noted']}/{res['jitter_total']} "
          f"({100*res['jitter_noted']/res['jitter_total']:.1f}%)"
          f"  分数 min={js[0]:.3f} p5={js[int(len(js)*0.05)]:.3f}")

    ok = (stats["PAGED"] / n <= 0.02
          and res["secret_detected"] / res["secret_total"] >= 0.95
          and res["jitter_noted"] / res["jitter_total"] >= 0.90)
    print("\n" + ("[PASS] 良性进值班<=2% 且 真信道发现>=95% 且 对抗留痕>=90%"
                  if ok else "[FAIL] 未达工程门槛"))
    sys.exit(0 if ok else 1)
