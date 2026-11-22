"""单元测试：把关键判据钉死，防止后续调参把误报/漏报改坏。"""
import unittest

from covert_exfil.pwm import analyze_channel, extract_bits
from covert_exfil.coincidence import cross_domain, rate_agreement
from covert_exfil.attribution import attribute, PwmWrite
from covert_exfil.scenarios import (
    fan_secret_channel, led_secret_channel, phys_mic_of_secret,
    benign_compile_load, benign_thermal_ramp, benign_thermal_oscillation,
    attack_jittered, attack_single_domain,
)


class TestChannelDetection(unittest.TestCase):
    def test_secret_channel_detected(self):
        t, v, _ = fan_secret_channel(64, 0.020, 0.0005, seed=7)
        f = analyze_channel("fan", "host", t, v)
        self.assertGreaterEqual(f.score, 0.80)
        self.assertIn("clocked_duty_modulation", f.flags)
        self.assertLess(f.period_cv, 0.05)

    def test_compile_load_not_detected(self):
        t, v = benign_compile_load(6000, 0.0005, seed=11)
        f = analyze_channel("fan", "host", t, v)
        self.assertLess(f.score, 0.30)

    def test_thermal_ramp_not_detected(self):
        t, v = benign_thermal_ramp(6000, 0.0005)
        f = analyze_channel("fan", "host", t, v)
        self.assertLess(f.score, 0.30)

    def test_static_oscillation_not_detected(self):
        """周期规则但占空比恒定 —— 最易误判的良性情形。"""
        t, v = benign_thermal_oscillation(4000, 0.0005)
        f = analyze_channel("fan", "host", t, v)
        self.assertLess(f.score, 0.30)
        self.assertIn("static_oscillation", f.flags)

    def test_jittered_attack_leaves_trace(self):
        """对抗抖动可降级，但绝不允许掉进黑洞。"""
        t, v, _ = attack_jittered(64, 0.020, 0.0005, seed=23)
        f = analyze_channel("fan", "host", t, v)
        self.assertGreaterEqual(f.score, 0.30)

    def test_short_record_is_penalized(self):
        t, v, _ = fan_secret_channel(3, 0.020, 0.0005, seed=1)
        f = analyze_channel("fan", "host", t, v)
        self.assertLess(f.score, 0.80)


class TestCrossDomain(unittest.TestCase):
    def test_three_domain_secret_confirms(self):
        ft, fv, _ = fan_secret_channel(64, 0.020, 0.0005, seed=7)
        mt, mv, _ = phys_mic_of_secret(64, 0.020, 0.0005, seed=7, snr=6.0)
        hf = analyze_channel("fan", "host", ft, fv)
        pf = analyze_channel("mic", "physical", mt, mv)
        v = cross_domain(hf, pf)
        self.assertIn(v.tier, ("CONFIRMED", "HIGH"))

    def test_same_domain_capped(self):
        """两个风扇同域一致不算独立证据，最高只到 MEDIUM。"""
        ft, fv, _ = fan_secret_channel(64, 0.020, 0.0005, seed=7)
        f2t, f2v, _ = fan_secret_channel(64, 0.020, 0.0005, seed=7)
        a = analyze_channel("fan0", "host", ft, fv)
        b = analyze_channel("fan1", "host", f2t, f2v)
        v = cross_domain(a, b)
        self.assertNotIn(v.tier, ("CONFIRMED", "HIGH"))

    def test_single_domain_not_confirmed(self):
        st, sv, _, bt, bv = attack_single_domain(64, 0.0005, seed=29)
        a = analyze_channel("fan", "host", st, sv)
        b = analyze_channel("mic", "physical", bt, bv)
        v = cross_domain(a, b)
        self.assertNotIn(v.tier, ("CONFIRMED", "HIGH"))

    def test_rate_agreement(self):
        self.assertAlmostEqual(rate_agreement(10.0, 10.0), 1.0)
        self.assertEqual(rate_agreement(10.0, 20.0), 0.0)
        self.assertGreater(rate_agreement(10.0, 11.0), 0.5)


class TestBitRecovery(unittest.TestCase):
    def test_bits_recovered_from_clean_channel(self):
        payload = (b"TOP-SECRET-ARCHIVE-2026-Q4//project_owl//keyslot-"
                   b"7//exfil-test-vector/")
        t, v, ref = fan_secret_channel(64, 0.020, 0.0005, seed=7)
        f = analyze_channel("fan", "host", t, v)
        got = extract_bits(f)
        want = bytes(int("".join(str(b) for b in ref[i:i+8]), 2)
                     for i in range(0, 64, 8))
        self.assertGreaterEqual(len(got), 7)  # 63 个完整周期 → 7 字节
        self.assertEqual(got, want[:len(got)])
        self.assertTrue(payload.startswith(got))


class TestAttribution(unittest.TestCase):
    def test_suspicious_writer_scores_high(self):
        ws = [PwmWrite(i * 0.005, 4412, "libcrypto-helper", "hwmon:pwm2",
                       0.35 if i % 2 else 0.65, 20000.0) for i in range(200)]
        a = attribute("hwmon:pwm2", ws)
        self.assertGreater(a.confidence, 0.6)
        self.assertEqual(a.writer_pid, 4412)

    def test_daemon_writer_scores_lower(self):
        ws = [PwmWrite(i * 0.5, 700, "fancontrol", "hwmon:pwm2",
                       0.5, 20000.0) for i in range(10)]
        a = attribute("hwmon:pwm2", ws)
        self.assertLess(a.confidence, 0.6)


if __name__ == "__main__":
    unittest.main(verbosity=2)
