import os
import sys

_TOOLS_DIR = os.path.join(os.path.dirname(__file__), '..', 'tools')

for _name in os.listdir(_TOOLS_DIR):
    _path = os.path.join(_TOOLS_DIR, _name)
    if os.path.isdir(_path):
        sys.path.insert(0, _path)
