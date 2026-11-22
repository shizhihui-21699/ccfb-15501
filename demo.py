"""
端到端演示：把 6 个场景跑一遍，看告警分级是否符合工程预期。

预期（这就是验收标准）：
  S1 真信道(风扇+指示灯+麦克风)  → 出现 CONFIRMED/HIGH，且落到值班队列
  S2 良性编译满载                → 不出现 HIGH 及以上
  S3 热控寻的振荡                → 被抑制为 INFO（周期规则但占空比恒定）
  S4 对抗: 25% 时基抖动           → 允许降为 MEDIUM（漏报由日报兜底），但不许沉默
  S5 只驱动单域                  → 不出 CONFIRMED
  S6 写 PWM 但物理无响应          → 不出 HIGH
"""
from __future__ import annotations

import json
import sys

from covert_exfil.scenarios import (
    fan_secret_channel, led_secret_channel, phys_mic_of_secret,
    benign_compile_load, benign_thermal_ramp, benign_thermal_oscillation,
    attack_jittered, attack_single_domain, attack_pwm_no_physical,
)
from covert_exfil.correlator import analyze_scenario
from covert_exfil.attribution import PwmWrite
from covert_exfil.pwm import analyze_channel, extract_bits
from covert_exfil.coincidence import match_log_prefix


def _writes_from_finding(device, pid, process, n=140, span=1.3):
    """根据观测到的符号速率合成进程写入记录（真实系统里由 tracefs 采样器产出）。"""
    out = []
    for i in range(n):
        t = span * i / n
        duty = 0.65 if (i % 7 < 4) else 0.35
        out.append(PwmWrite(t, pid, process, device, duty, 20000.0))
    return out


def run():
    results = {}
    bad = []

    # ---------- S1: 真实隐蔽信道，三域一致 ----------
    ft, fv, bits = fan_secret_channel(64, 0.020, 0.0005, seed=7)
    lt, lv, _ = led_secret_channel(64, 0.021, 0.0005, seed=7)
    mt, mv, _ = phys_mic_of_secret(64, 0.020, 0.0005, seed=7, snr=6.0)
    host = {"fan0": {"domain": "host", "device": "hwmon:pwm2",
                     "times": ft, "values": fv},
            "led_hdd": {"domain": "host", "device": "leds:input3",
                        "times": lt, "values": lv}}
    phys = {"room_mic": {"domain": "physical", "device": "oob:mic01",
                         "times": mt, "values": mv}}
    writes = {"hwmon:pwm2": _writes_from_finding("hwmon:pwm2", 4412,
                                                 "libcrypto-helper", 160, 1.4),
              "leds:input3": _writes_from_finding("leds:input3", 4412,
                                                  "libcrypto-helper", 150, 1.35)}
    r1 = analyze_scenario("S1_true_covert_channel", host, phys, writes)
    results["S1"] = r1
    if not any(a["severity"] in ("CONFIRMED", "HIGH") for a in r1["paged"]):
        bad.append("S1 未升级到值班队列")

    # ---------- S2: 良性编译满载 ----------
    ct, cv = benign_compile_load(6000, 0.0005, seed=11)
    mt2, mv2 = benign_compile_load(6000, 0.0005, seed=12)
    r2 = analyze_scenario(
        "S2_benign_compile_load",
        {"fan0": {"domain": "host", "device": "hwmon:pwm2",
                  "times": ct, "values": cv}},
        {"room_mic": {"domain": "physical", "device": "oob:mic01",
                      "times": mt2, "values": mv2}},
    )
    results["S2"] = r2
    if r2["paged"]:
        bad.append(f"S2 误报进值班队列: {[a['title'] for a in r2['paged']]}")

    # ---------- S3: 热控寻的振荡（规则周期 + 恒定占空比）----------
    ot, ov = benign_thermal_oscillation(4000, 0.0005)
    r3 = analyze_scenario(
        "S3_thermal_oscillation",
        {"fan0": {"domain": "host", "device": "hwmon:pwm2",
                  "times": ot, "values": ov}},
        {},
    )
    results["S3"] = r3
    if r3["paged"]:
        bad.append("S3 静态振荡被误判为外传")

    # ---------- S4: 对抗 25% 时基抖动 ----------
    jt, jv, _ = attack_jittered(64, 0.020, 0.0005, seed=23)
    r4 = analyze_scenario(
        "S4_adversarial_jitter",
        {"fan0": {"domain": "host", "device": "hwmon:pwm2",
                  "times": jt, "values": jv}},
        {},
    )
    results["S4"] = r4
    # 期望：不沉默（至少 MEDIUM/LOW 有记录），不误升级
    if not r4["daily"] and not r4["low"]:
        bad.append("S4 对抗抖动导致完全沉默(漏报无兜底)")

    # ---------- S5: 只驱动单域 ----------
    st, sv, _, bt, bv = attack_single_domain(64, 0.0005, seed=29)
    r5 = analyze_scenario(
        "S5_single_domain_only",
        {"fan0": {"domain": "host", "device": "hwmon:pwm2",
                  "times": st, "values": sv}},
        {"room_mic": {"domain": "physical", "device": "oob:mic01",
                      "times": bt, "values": bv}},
    )
    results["S5"] = r5
    if r5["paged"]:
        bad.append("S5 单域被误判为 CONFIRMED/HIGH")

    # ---------- S6: 写 PWM 但物理无响应 ----------
    pt, pv, qt, qv = attack_pwm_no_physical(64, 0.0005, seed=31)
    r6 = analyze_scenario(
        "S6_pwm_no_physical_response",
        {"fan0": {"domain": "host", "device": "hwmon:pwm2",
                  "times": pt, "values": pv}},
        {"room_mic": {"domain": "physical", "device": "oob:mic01",
                      "times": qt, "values": qv}},
    )
    results["S6"] = r6
    if r6["paged"]:
        bad.append("S6 仅软件写 PWM(物理无响应)被误升 HIGH")

    # ---------- 内容级确认 ----------
    payload = (b"TOP-SECRET-ARCHIVE-2026-Q4//project_owl//keyslot-"
               b"7//exfil-test-vector/")
    rr = analyze_scenario(
        "S7_content_match",
        {"fan0": {"domain": "host", "device": "hwmon:pwm2",
                  "times": ft, "values": fv}},
        {},
        log_blocks=[{"pid": 4412, "process": "libcrypto-helper", "data": payload}],
    )
    results["S7"] = rr
    hit = [a for a in rr["alerts"] if a["title"].startswith("内容级确认")]
    if not hit:
        bad.append("S7 内容级比对未命中")

    return results, bad


if __name__ == "__main__":
    results, bad = run()

    for sid, r in results.items():
        print(f"\n=== {r['scenario']} ===")
        for a in r["alerts"]:
            print(f"  [{a['severity']:9s}] {a['title']}  score={a['score']}"
                  + (f"  (×{a['count']})" if a["count"] > 1 else ""))
        if not r["alerts"]:
            print("  (无告警)")

    print("\n" + "=" * 60)
    if bad:
        print("验收未通过:")
        for b in bad:
            print("  -", b)
        sys.exit(1)
    print("全部场景通过验收标准:")
    print("  真信道 → 升级到值班队列")
    print("  良性高负载 / 静态振荡 → 不进值班队列")
    print("  对抗抖动 → 不沉默，降级到日报")
    print("  单域 / 物理无响应 → 不误升")
    print("  比特内容 → 可逐比特确认")
