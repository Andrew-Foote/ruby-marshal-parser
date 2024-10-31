import functools as ft
import importlib.resources
import json
from pathlib import Path
import pytest
import ruby_marshal_parser as marshal

@ft.cache
def golden_path():
	with importlib.resources.path('ruby_marshal_parser') as base_path:
		return base_path.parent / 'tests/golden'

@pytest.fixture
def update_golden_inputs(request):
	return request.config.getoption('--update-golden')

def test_to_json_dumpable(update_golden_inputs):
	inputs_tested = set()

	for input_path in (golden_path() / 'inputs').iterdir():
		output = json.dumps(
			marshal.parse_file(input_path).to_json_dumpable(),
			indent=2
		)

		output_path = golden_path() / f'outputs/{input_path.name}'

		if output_path.exists() and not update_golden_inputs:
			with output_path.open() as output_file:
				output_content = output_file.read()

			assert output == output_content
		else:
			with output_path.open('w') as output_file:
				output_file.write(output)

		inputs_tested.add(input_path.name)

	for output_path in (golden_path() / 'outputs').iterdir():
		if output_path.name not in inputs_tested:
			output_path.unlink()