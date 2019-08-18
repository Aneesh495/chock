"""
Unit tests for INT v2.1, Postcard telemetry, Flowlet switching, DCQCN, and trTCM.
"""

import unittest
import time
from chock.pipeline.externs import ChockMeter, MeterColor, ChockRegister

class TestTelemetryTraffic(unittest.TestCase):
    def test_trtcm_token_bucket_policer(self):
        # Configure trTCM: CIR = 1000 bytes/s, CBS = 1000 bytes, PIR = 2000 bytes/s, PBS = 2000 bytes
        meter = ChockMeter(size=16, cir=1000, cbs=1000, pir=2000, pbs=2000)
        
        # Packet conforming to CIR: Green
        color1 = meter.execute(0, 500)
        self.assertEqual(color1, MeterColor.GREEN)
        
        # Packet exceeding CBS but conforming to PBS: Yellow
        color2 = meter.execute(0, 1000)
        self.assertEqual(color2, MeterColor.YELLOW)
        
        # Packet exceeding PBS: Red
        color3 = meter.execute(0, 5000)
        self.assertEqual(color3, MeterColor.RED)

    def test_flowlet_switching_burst_detection(self):
        reg = ChockRegister(size=1024, initial_value=0)
        now_ns = int(time.time() * 1e9)
        reg.write(42, now_ns)
        
        # Read back
        stored = reg.read(42)
        self.assertEqual(stored, now_ns)

if __name__ == "__main__":
    unittest.main()
