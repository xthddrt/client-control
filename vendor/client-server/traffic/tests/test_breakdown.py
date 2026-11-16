import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "traffic_breakdown", Path(__file__).resolve().parents[2] / "analysis" / "traffic-breakdown.py")
breakdown = importlib.util.module_from_spec(spec)
spec.loader.exec_module(breakdown)


class ClassifyTest(unittest.TestCase):
    def test_categories_by_game_handshake_server_name_then_port(self):
        self.assertEqual(breakdown.classify({"destination": ["1.2.3.4", 8484], "game_handshake": True})[0],
                         "Game: login server")
        self.assertEqual(breakdown.classify({"destination": ["1.2.3.4", 8557], "game_handshake": True})[0],
                         "Game: channel servers")
        self.assertEqual(breakdown.classify({"destination": ["1.2.3.4", 443], "sni": "public.api.nexon.com"})[0],
                         "Analytics")
        self.assertEqual(breakdown.classify({"destination": ["1.2.3.4", 47611]})[0], "Nexon messenger/session")
        self.assertEqual(breakdown.classify({"destination": ["1.2.3.4", 443], "sni": "example.com"})[0],
                         "Other: HTTPS example.com")
        # a game port without a game handshake is not counted as the game
        self.assertEqual(breakdown.classify({"destination": ["1.2.3.4", 8484]})[0], "Other: port 8484")


if __name__ == "__main__":
    unittest.main()
