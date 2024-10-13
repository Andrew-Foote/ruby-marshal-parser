# ruby-marshal-parser

This is a package for parsing data in Ruby's Marshal serialisation format (see [https://docs.ruby-lang.org/en/master/marshal_rdoc.html#label-Marshal+Format](https://docs.ruby-lang.org/en/master/marshal_rdoc.html#label-Marshal+Format)).

## Usage

### JSON output

A simple way to use the package is to convert the data to JSON. You can do this by running the module as a CLI program:

    python -m ruby_marshal_parser path/to/input.dat path/to/output.json

To do it within a Python script, you can use the code like the following:

	import json
	import ruby_marshal_parser as marshal

	with open('path/to/input.dat', 'rb') as f:
		raw_data = marshal.parse_stream(f)

	data = raw_data.to_json_dumpable()
	print(json.dumps(data))

### Raw output

Alternatively, you may want to work directly with the raw parse tree returned from `parse_stream`. This will be a `MarshalFile` object, which has two important attributes:

* `version`, which is a `MarshalVersion` object, with `major` and `minor` attributes giving the major and minor version number, respectively.
* `content`, which is a `Node` object.

A `Node` object consists of a link back to the parent `MarshalFile`, via the `file` attribute, and a `NodeData` object, which is stored in the `content` attribute. `NodeData` objects come in 25 types, matching the 25 possible type bytes in the Marshal format.

| Byte (as ASCII character) | Class name             |
| ------------------------- | ---------------------- |
| `T`                       | `True_`                |
| `F`                       | `False_`               |
| `0`                       | `Nil`                  |
| `i`                       | `Fixnum`               |
| `:`                       | `Symbol`               |
| `;`                       | `SymbolRef`            |
| `@`                       | `ObjectRef`            |
| `I`                       | `InstVars`             |
| `e`                       | `ModuleExt`            |
| `[`                       | `ArrayNode`            |
| `l`                       | `Bignum`               |
| `c`                       | `ClassRef`             |
| `m`                       | `ModuleRef`            |
| `M`                       | `ClassOrModuleRef`     |
| `d`                       | `Data`                 |
| `f`                       | `Float`                |
| `{`                       | `Hash`                 |
| `}`                       | `DefaultHash`          |
| `o`                       | `Object`               |
| `/`                       | `Regex`                |
| `"`                       | `String`               |
| `S`                       | `Struct`               |
| `C`                       | `UserClass`            |
| `u`                       | `UserData`             |
| `U`                       | `UserObject`           |

Nodes do not necessarily correspond in a one-to-one way to Ruby objects. There are two kinds of nodes which do not represent Ruby objects directly: reference nodes and extension nodes.

Reference nodes are those whose `content` is of type `SymbolRef` or `ObjectRef`. These are pointers to nodes representing Ruby objects which occur elsewhere in the parse tree; the Marshal format uses these whenever an object is referenced multiple times in the data. To follow the reference you can access the `deref` property of the node. For nodes whose `content` is not of type `SymbolRef` or `ObjectRef`, the `deref` property will just return the node itself.

Extension nodes are those of type `InstVars` and `ModuleExt`. These wrap around a node representing a Ruby object, and extend it with additional data. To get the node corresponding to the Ruby object, you can use the `body` property, which descends into the wrapped nodes, stopping and returning the node once it reaches one which is not of type `InstVars` or `ModuleExt`.

The `inst_vars` and `module_ext` properties can also be used to access the additional data that the object is extended with. `inst_vars` is a dictionary mapping the names of instance variables to their values, and `module_ext` is a list of names of modules. Note that for nodes whose `content` is of type `Object` or `Struct`, the `inst_vars` property will also include the instance variables stored directly within these `Object` or `Struct` objects (as well as the ones in any `InstVars` nodes wrapping them).

### Character encodings

The Marshal format doesn't use a fixed encoding for textual data. The `NodeData` types which contain textual data are `Symbol`, `ClassRef`, `ModuleRef`, `ClassOrModuleRef`, `Regex`, and `String`. All of these classes have a `text` attribute which is of type `bytes`. To get the decoded text, you can use the `decoded_text` property on the `Node` containing the textual data. This property belongs to `NodeData`, not `NodeData`, since it needs to look at the instance variables to determine the encoding.

Encodings are supposed to be specified by an instance variable named `'E'`, which may take a Boolean true value (indicating UTF-8), a Boolean false value (indicating US-ASCII), or a string indicating an encoding by name. The Ruby documentation doesn't say what it means if this instance variable is absent, so in the absence of any official guidance, this program will try to decode the text using the `latin-1` encoding.

### Pattern-matching syntax

I've tried to make the program work nicely with Python's pattern-matching syntax. The `__match_args__` for a `Node` object is a tuple of the following three properties: `body_type_and_content`, `inst_vars`, and `module_ext`. The last two properties are already mentioned above. As for the first, this will be a tuple consisting of the node's type code (e.g. `T`, `F`, or `0`; see the table above), along with some other items taken from the node's `content`, which are generally more "parsed" than "raw". For example, for fixnums this would be the fixnum value, as an `int`; for strings, it would be the decoded text of the string. Here is an example of how you might use this:

	match node:
		case Node(['o', 'RPG::MapInfo'], {
			'@name': Node(['"', name]),
			'@parent_id': Node(['i', parent_id]),
			'@order': Node(['i', order]),
			'@expanded': Node([('T' | 'F') as expanded]),
			'@scroll_x': Node(['i', scroll_x]),
			'@scroll_y': Node(['i', scroll_y])
		} as attrs):
			return cls(
				name=name,
				parent_id=parent_id,
				order=order,
				expanded=expanded == 'T',
				scroll_x=scroll_x,
				scroll_y=scroll_y
			)
