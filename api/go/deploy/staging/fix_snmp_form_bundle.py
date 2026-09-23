"""Fix the initialization order in the archived staging frontend bundle.

The local frontend source is a different revision. Apply only to the verified
deployed bundle; keep the immediate watcher after its form ref declaration.
"""
import pathlib
import sys


def fix(source):
    watch = "bn(()=>S.value.device_type,g,{immediate:!0});"
    anchor = "x=ce([]),E=ce(!1);"
    if source.count(watch) != 1 or source.count(anchor) != 1:
        raise ValueError("Unexpected frontend bundle; refusing to patch")
    if source.index(watch) > source.index(anchor):
        return source
    result = source.replace(watch, "", 1).replace(anchor, anchor + watch, 1)
    assert result.index("S=ce(t.device?") < result.index(watch)
    return result


if __name__ == "__main__":
    path = pathlib.Path(sys.argv[1])
    path.write_text(fix(path.read_text()))
