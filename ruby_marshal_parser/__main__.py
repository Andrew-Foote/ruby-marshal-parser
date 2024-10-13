import argparse
import json
from pathlib import Path
from ruby_marshal_parser import *

arg_parser = argparse.ArgumentParser(
    prog='ruby_marshal_parser',
    description='Parses Ruby Marshal data files.'
)

arg_parser.add_argument('input_file', type=Path)
arg_parser.add_argument('output_file', type=Path)
parsed_args = arg_parser.parse_args()

with parsed_args.input_file.open('rb') as f:
    raw_tree = parse_stream(f)

json_tree = json.dumps(raw_tree.to_json_dumpable(), indent=2)

with parsed_args.output_file.open('w') as f:
    f.write(json_tree)
