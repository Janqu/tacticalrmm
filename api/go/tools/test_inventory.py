import tempfile
import unittest
from pathlib import Path

from inventory import scan


class InventoryTest(unittest.TestCase):
    def test_gates_dynamic_routes_and_source_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "urls.py"
            path.write_text('''
from django.urls import path, include
urlpatterns = [path("", home)]
if settings.ENABLED:
    urlpatterns += [path("api/", include("agents.urls"))]
else:
    urlpatterns += [path("disabled/", disabled)]
router.register("agent", AgentViewSet)
''')
            (root / ".venv").mkdir()
            (root / ".venv" / "ignored.py").write_text("not valid python!")
            first = scan(root)
            self.assertEqual(len(first["routes"]), 4)
            self.assertEqual(first["routes"][1]["conditions"], ["settings.ENABLED"])
            self.assertEqual(first["routes"][2]["conditions"], ["not (settings.ENABLED)"])
            self.assertEqual(first["routes"][3]["kind"], "router")
            self.assertEqual(len(first["sources"]), 1)
            path.write_text(path.read_text() + "\n# changed\n")
            self.assertNotEqual(first["sources"], scan(root)["sources"])


if __name__ == "__main__":
    unittest.main()
