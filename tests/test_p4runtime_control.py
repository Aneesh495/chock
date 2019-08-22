"""
Unit tests for P4Runtime control plane table rules and telemetry.
"""

import unittest
from chock.pipeline import ChockSwitchPipeline
from chock.control import P4RuntimeServer, P4RuntimeEntity, UpdateType

class TestP4RuntimeControl(unittest.TestCase):
    def setUp(self):
        self.sw = ChockSwitchPipeline()
        self.server = P4RuntimeServer(self.sw)

    def test_table_entry_insert_and_delete(self):
        entity = P4RuntimeEntity(
            table_name="ipv4_fib_lpm",
            match_fields={"dst_ip": 0x0A010203},
            action_name="set_next_hop_unicast",
            action_params={"port": 7},
            priority=150
        )
        # INSERT
        ok = self.server.write_table_entry(UpdateType.INSERT, entity)
        self.assertTrue(ok)
        self.assertEqual(len(self.sw.ipv4_lpm_table.entries), 1)
        
        # DELETE
        ok_del = self.server.write_table_entry(UpdateType.DELETE, entity)
        self.assertTrue(ok_del)
        self.assertEqual(len(self.sw.ipv4_lpm_table.entries), 0)

    def test_counter_read(self):
        self.sw.port_counters.count(3, 128)
        counters = self.server.read_counters(3)
        self.assertEqual(counters["packets"], 1)
        self.assertEqual(counters["bytes"], 128)

if __name__ == "__main__":
    unittest.main()
