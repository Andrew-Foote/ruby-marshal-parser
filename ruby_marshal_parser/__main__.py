import argparse
import json
from pathlib import Path
from ruby_marshal_parser import *

arg_parser = argparse.ArgumentParser(
    prog='ruby_marshal_parser',
    description=(
        'Parses Ruby Marshal data files and prints the result in a '
        'representation as JSON.'
    )
)

arg_parser.add_argument('input_file', type=Path, help='the file to parse')
parsed_args = arg_parser.parse_args()

with parsed_args.input_file.open('rb') as f:
    raw_tree = parse_stream(f)

print(json.dumps(raw_tree.to_json_dumpable(), indent=2))