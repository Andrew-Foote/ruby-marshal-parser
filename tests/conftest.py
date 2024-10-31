from _pytest.fixtures import Parser

def pytest_addoption(parser: Parser):
	parser.addoption('--update-golden', action='store_true')
