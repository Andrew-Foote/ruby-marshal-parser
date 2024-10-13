# ruby-marshal-parser

This is a package for parsing data in Ruby's Marshal serialisation format (see [https://docs.ruby-lang.org/en/master/marshal_rdoc.html#label-Marshal+Format](https://docs.ruby-lang.org/en/master/marshal_rdoc.html#label-Marshal+Format)).

## Usage

### JSON output

A simple way to use the package is to convert the data to JSON, as in the following example:

```
import json
import ruby_marshal_parser as marshal

with open('path/to/some/marshal/data') as f:
	raw_data = marshal.parse_stream(f)

data = raw_data.to_json_dumpable()
print(json.dumps(data))
```

### Raw output

Alternatively, you may want to work directly with the raw parse tree returned from `parse_stream`. This will be a `MarshalFile` object, which has two important attributes:

* `version`, which is a `MarshalVersion` object, with `major` and `minor` attributes giving the major and minor version number, respectively.
* `content`, which is a `Node` object.

`Node` objects come in 25 types, matching the 25 possible type bytes in the Marshal format.

| Byte (as ASCII character) | Class name             |
| ------------------------- | ---------------------- |
| `T`                       | `TrueNode`             |
| `F`                       | `FalseNode`            |
| `0`                       | `NilNode`              |
| `i`                       | `FixnumNode`           |
| `:`                       | `SymbolNode`           |
| `;`                       | `SymbolRefNode`        |
| `@`                       | `ObjectRefNode`        |
| `I`                       | `InstVarsNode`         |
| `e`                       | `ModuleExtNode`        |
| `[`                       | `ArrayNode`            |
| `l`                       | `BignumNode`           |
| `c`                       | `ClassRefNode`         |
| `m`                       | `ModuleRefNode`        |
| `M`                       | `ClassOrModuleRefNode` |
| `d`                       | `DataNode`             |
| `f`                       | `FloatNode`            |
| `{`                       | `HashNode`             |
| `}`                       | `DefaultHashNode`      |
| `o`                       | `ObjectNode`           |
| `/`                       | `RegexNode`            |
| `"`                       | `StringNode`           |
| `S`                       | `StructNode`           |
| `C`                       | `UserClassNode`        |
| `u`                       | `UserDataNode`         |
| `U`                       | `UserObjectNode`       |

These nodes do not all represent Ruby objects directly. There are two kinds of nodes which do not represent Ruby objects directly: reference nodes and extension nodes.

Reference nodes are those of type `SymbolRefNode` or `ObjectRefNode`. These are pointers to nodes representing Ruby objects which occur elsewhere in the parse tree; the Marshal format uses these whenever an object is referenced multiple times in the data. The `deref()` method can be called on a node to follow these references. When called on a `SymbolRefNode` or `ObjectRefNode`, it will return the referenced node; otherwise, it will return the same node you called it on. Note that in order to make this possible, each `Node` contains a cyclic reference to the `MarshalFile` it came from.

Extension nodes are those of type `InstVarsNode` and `ModuleExtNode`. These wrap around a node representing a Ruby object, and extend it with additional data. To get the Ruby object corresponding it 

Apart from 

These two reference types, along with nodes of type `InstVarsNode` and `ModuleExtNode`, are 

Each node also has `inst_vars` and `module_ext` attributes which contain the instance variables belonging to the node, and the modules the node is extended by, respectively. These are computed by checking whether the node is an `InstVarsNode` or `ModuleExtNode`