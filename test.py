import json
from pathlib import Path
import sys
from ruby_marshal_parser import __main__ as marshal

name = sys.argv[1]
path = Path(f'/home/andrew/Programs/Pokemon Rejuvenation/Data/{name}')
root = marshal.parse_file(path)
print(json.dumps(root.to_json_dumpable(), indent=2))