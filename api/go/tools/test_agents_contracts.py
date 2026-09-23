import unittest

from compare_agents_reads import response_body


class AgentResponseTests(unittest.TestCase):
    def test_only_unordered_top_level_lists_are_sorted(self):
        rows = [{"id": 2}, {"id": 1}]
        self.assertEqual(response_body(rows), list(reversed(rows)))
        self.assertEqual(response_body({"results": rows}), {"results": rows})
        self.assertEqual(response_body("Cannot add an empty note"), "Cannot add an empty note")


if __name__ == "__main__":
    unittest.main()
