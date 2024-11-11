import functools as ft
import importlib.resources
import json
from pathlib import Path
import pytest
from _pytest.fixtures import FixtureRequest
import ruby_marshal_parser as marshal

@ft.cache
def golden_path() -> Path:
	with importlib.resources.path('ruby_marshal_parser') as base_path:
		return base_path.parent / 'golden'

@pytest.fixture
def update_golden_inputs(request: FixtureRequest) -> bool:
	return request.config.getoption('--update-golden')

def test_to_json_dumpable(update_golden_inputs: bool) -> None:
	inputs_tested = set()

	for input_path in (golden_path() / 'inputs').iterdir():
		try:
			output = json.dumps(
				marshal.parse_file(input_path).to_json_dumpable(),
				indent=2
			)
		except Exception as e:
			e.add_note(str(input_path))
			raise

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