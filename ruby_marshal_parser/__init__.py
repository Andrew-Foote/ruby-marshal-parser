from abc import ABC
from dataclasses import dataclass, field
import functools as ft
import io
import locale
import math
from pathlib import Path
import re
from typing import assert_never, Callable, Literal, Iterator, Sequence, Mapping
from warnings import warn


def dfs[T](node: T, children: Callable[[T], Iterator[T]]) -> Iterator[T]:
    yield node

    for child in children(node):
        yield from dfs(child, children)


JsonDumpable = (
    bool | None | int | float | str
    | Sequence['JsonDumpable'] | Mapping[str, 'JsonDumpable']
)


class DataError(Exception):
    pass

@dataclass(frozen=True)
class MarshalVersion:
    major: int
    minor: int

    def __str__(self) -> str:
        return f'{self.major}.{self.minor}'
    
    def is_supported(self):
        return (self.major, self.minor) <= (4, 8)

@dataclass(eq=False)
class MarshalFile:
    version: MarshalVersion=MarshalVersion(0, 0)
    content: 'Node | None'=None

    def __str__(self) -> str:
        return str(self.to_json_dumpable())

    @ft.cached_property
    def symbols(self) -> list['Node']:
        assert self.content is not None

        return [
            node for node in dfs(self.content, Node.children)
            if node.can_be_symbol_ref_target()
        ]

    @ft.cached_property
    def objects(self) -> list['Node']:
        assert self.content is not None

        return [
            node for node in dfs(self.content, Node.children)
            if node.can_be_object_ref_target()
        ]

    def to_json_dumpable(self) -> JsonDumpable:
        if self.content is None:
            assert False, 'MarshalFile not initialized'

        return {
            'version': str(self.version),
            'content': self.content.to_json_dumpable()
        }

@dataclass(eq=False)
class NodeData(ABC):
    pass

NodeBodyTypeAndContent = (
    tuple[Literal['T']] | tuple[Literal['F']]
    | tuple[Literal['0']]
    | tuple[Literal['i'], int]
    | tuple[Literal[':'], str]
    | tuple[Literal['['], list['Node']]
    | tuple[Literal['l'], int]
    | tuple[Literal['c'], str]
    | tuple[Literal['m'], str]
    | tuple[Literal['M'], str]
    | tuple[Literal['d'], str, 'Node']
    | tuple[Literal['f'], float]
    | tuple[Literal['{'], list[tuple['Node', 'Node']]]
    | tuple[Literal['}'], list[tuple['Node', 'Node']], 'Node']
    | tuple[Literal['/'], str, set[re.RegexFlag]]
    | tuple[Literal['"'], str]
    | tuple[Literal['o'], str]
    | tuple[Literal['S'], str]
    | tuple[Literal['C'], str, 'Node']
    | tuple[Literal['u'], str, bytes]
    | tuple[Literal['U'], str, 'Node']
)

@dataclass(eq=False)
class Node:
    """A node in the parsed syntax tree."""

    file: MarshalFile
    content: NodeData

    __match_args__ = 'body_type_and_content', 'inst_vars', 'module_ext'

    def __str__(self) -> str:
        return str(self.to_json_dumpable())

    def children(self) -> Iterator['Node']:
        """Returns an iterator over the node's immediate children.

        For extension nodes (whose `content` is of type `InstVarsData` or
        `ModuleExtData`) the node corresponding to the extended object is not
        considered an immediate child; instead, its children are included
        among its parent's immediate children."""

        content = self.content

        match content:
            case (
                True_() | False_() | Nil() | Fixnum() | Symbol() | SymbolRef()
                | ObjectRef() | Bignum() | Float() | Regex() | String()
            ):
                pass
            case InstVars(child, members_list):
                yield from child.children()

                for key, value in members_list:
                    yield key
                    yield value 
            case ModuleExt(module_node, child):
                yield module_node
                yield from child.children()
            case Array(items):
                yield from items
            case Data(class_node, state):
                yield class_node
                yield state
            case Hash(items):
                for key, value in items:
                    yield key
                    yield value
            case DefaultHash(items, default):
                for key, value in items:
                    yield key
                    yield value

                yield default
            case Object(class_node, members) | Struct(class_node, members):
                yield class_node

                for key, value in members:
                    yield key
                    yield value
            case UserClass(class_node, child) | UserObject(class_node, child):
                yield class_node
                yield child
            case UserData(class_node, data):
                yield class_node
            case _:
                assert False, (
                    f'unrecognized node type {type(content).__name__}'
                )

    def can_be_symbol_ref_target(self) -> bool:
        return isinstance(self.content, Symbol)

    def can_be_object_ref_target(self) -> bool:
        return not isinstance(self.content, (
            True_, False_, Nil, Fixnum, Symbol, SymbolRef, ObjectRef
        ))

    @ft.cached_property
    def deref(self) -> 'Node':
        """Returns the referenced node, if the node is a reference node, and
        the node itself, otherwise.

        A reference node is one whose `content` is of type `SymbolRef` or
        `ObjectRef`."""

        result = self
        file = self.file

        while True:
            match result.content:
                case SymbolRef(value):
                    try:
                        return file.symbols[value]
                    except IndexError:
                        raise DataError(
                            'invalid symbol reference (referenced symbol '
                            f'number {value}, but only {len(file.symbols)} '
                            'symbols were found)'
                        )
                case ObjectRef(value):
                    try:
                        return file.objects[value]
                    except IndexError:
                        raise DataError(
                            'invalid object reference (referenced object '
                            f'number {value}, but only {len(file.objects)} '
                            'objects were found)'
                        )
                case _:
                    break

        return result

    @ft.cached_property
    def body(self) -> 'Node':
        """Returns the extended node, if the node is an extension node, and the
        node itself, otherwise.

        An extension node is one whose `content` is of type `InstVars` or
        `ModuleExt`."""

        result = self.deref

        while True:
            match result.content:
                case InstVars(child):
                    result = child
                case ModuleExt(_, child):
                    result = child
                case _:
                    break

        return result

    @property
    def body_content(self) -> NodeData:
        return self.body.content

    @ft.cached_property
    def inst_vars(self) -> dict[str, 'Node']:
        result: dict[str, Node] = {}
        node = self.deref

        while True:
            match node.content:
                case InstVars(child, members=members):
                    result |= members
                    node = child
                case ModuleExt(_, child):
                    node = child
                case Object(_, members=members):
                    result |= members
                    break
                case Struct(_, members=members):
                    result |= members
                    break
                case _:
                    break

        return result

    @ft.cached_property
    def module_ext(self) -> list[str]:
        result = []
        node = self.deref

        while True:
            match node.content:
                case InstVars(child):
                    node = child
                case ModuleExt(module_name=module, child=child):
                    result.append(module)
                    node = child
                case _:
                    break

        return result

    def as_encoding(self) -> str:
        match self.body_content:
            case True_():
                return 'utf-8'
            case False_():
                return 'us-ascii'
            case String(value):
                encoding_name = value.decode('utf-8')

                try:
                    b'\x00'.decode(encoding_name)
                except LookupError:
                    raise DataError(
                        f"Ruby encoding name '{encoding_name}' is not "
                        'understood by Python'
                    )

                return encoding_name
            case _:
                raise DataError(
                    f"node of type {type(self).__name__} can't be interpreted "
                    'as an encoding'
                )

    def encoding(self) -> str | None:
        encoding_node = self.inst_vars.get('E')
        return None if encoding_node is None else encoding_node.as_encoding()

    @property
    def decoded_text(self) -> str:
        content = self.body_content

        if not isinstance(content, (
            Symbol, ClassRef, ModuleRef, ClassOrModuleRef, Regex, String
        )):
            raise DataError(
                f'node of type {type(content).__name__} has no text to decode'
            )

        encoding = self.encoding()

        if encoding is None:
            return content.text.decode('utf-8', 'surrogateescape')
        else:
            return content.text.decode(encoding)

    @property
    def body_type_and_content(self) -> NodeBodyTypeAndContent:
        content = self.body_content

        match content:
            case True_():
                return 'T',
            case False_():
                return 'F',
            case Nil():
                return '0',
            case Fixnum(value):
                return 'i', value
            case Symbol():
                return ':', self.decoded_text
            case Array(items):
                return '[', items
            case Bignum(value):
                return 'l', value
            case ClassRef():
                return 'c', self.decoded_text
            case ModuleRef():
                return 'm', self.decoded_text
            case ClassOrModuleRef():
                return 'M', self.decoded_text
            case Data(class_name=klass, state=state):
                return 'd', klass, state
            case Float(value):
                return 'f', value
            case Hash(items):
                return '{', items
            case DefaultHash(items, default):
                return '}', items, default
            case Object(class_name=klass):
                return 'o', klass
            case Regex(options=options):
                return '/', self.decoded_text, options
            case String():
                return '"', self.decoded_text
            case Struct(class_name=klass):
                return 'S', klass
            case UserClass(class_name=klass, child=child):
                return 'C', klass, child
            case UserData(class_name=klass, data=data):
                return 'u', klass, data
            case UserObject(class_name=klass, child=child):
                return 'U', klass, child
            case _:
                assert False, (
                    f'node body has unexpected type {type(content).__name__}'
                )

    @property
    def symbol_text(self) -> str:
        content = self.body_content

        if not isinstance(content, Symbol):
            raise DataError(
                f'expected symbol node, got one of type '
                f'{type(content).__name__}'
            )

        return self.decoded_text

    @property
    def bool_value(self) -> bool:
        content = self.body_content

        match content:
            case True_():
                return True
            case False_():
                return False 
            case _:
                raise DataError(
                    f'expected true or false node, got one of type '
                    f'{type(content).__name__}'
                )

    def to_json_dumpable(self, parents: dict[Node, int] | None=None):
        if parents is None:
            parents = {}

        def recurse(node):
            return node.to_json_dumpable(parents)

        result: dict[str, JsonDumpable] = {}

        node = self.deref

        if node in parents:
            return {'type': 'parent-ref', 'value': parents[node]}
        
        parents[node] = len(parents)

        if node.module_ext:
            result['module_ext'] = node.module_ext

        content = node.body_content

        match content:
            case True_():
                result['type'] = 'true'
                result['value'] = True
            case False_():
                result['type'] = 'false'
                result['value'] = False
            case Nil():
                result['type'] = 'nil'
                result['value'] = None
            case Fixnum(value):
                result['type'] = 'fixnum'
                result['value'] = value
            case Symbol():
                result['type'] = 'symbol'
                result['value'] = node.decoded_text
            case Array(items):
                result['type'] = 'array'
                result['value'] = list(map(recurse, items))
            case Bignum(value):
                result['type'] = 'bignum'
                result['value'] = value
            case ClassRef():
                result['type'] = 'class-ref'
                result['value'] = node.decoded_text
            case ModuleRef():
                result['type'] = 'module-ref'
                result['value'] = node.decoded_text
            case ClassOrModuleRef():
                result['type'] = 'class-or-module-ref'
                result['value'] = node.decoded_text
            case Data(class_name=klass, state=state):
                result['type'] = 'data'
                result['class'] = klass
                result['state'] = recurse(state)
            case Float(value):
                result['type'] = 'float'
                result['value'] = value
            case Hash(items):
                result['type'] = 'hash'
                
                result['value'] = [
                    (recurse(key), recurse(value)) for key, value in items
                ]
            case DefaultHash(items, default):
                result['type'] = 'hash'
                
                result['value'] = [
                    (recurse(key), recurse(value)) for key, value in items
                ]

                result['default'] = recurse(default)
            case Object(class_name=klass):
                result['type'] = 'object'
                result['class'] = klass
            case Regex(options=options):
                result['type'] = 'regex'
                result['source'] = node.decoded_text
                result['options'] = [option.value for option in options]
            case String():
                result['type'] = 'string'
                result['value'] = node.decoded_text
            case Struct(class_name=klass):
                result['type'] = 'struct'
                result['class'] = klass
            case UserClass(class_name=klass, child=child):
                result['type'] = 'user-class'
                result['class'] = klass
                result['child'] = recurse(child)
            case UserData(class_name=klass, data=data):
                result['type'] = 'user-data'
                result['class'] = klass
                result['data'] = data.decode('latin-1')
            case UserObject(class_name=klass, child=child):
                result['type'] = 'user-object'
                result['class'] = klass
                result['child'] = recurse(child)
            case _:
                assert False, (
                    f'unrecognized node type: {type(content).__name__}'
                )

        result['inst_vars'] = {
            name: recurse(value)
            for name, value in node.inst_vars.items()
            if name != 'E'
        }

        del parents[node]

        if not result['inst_vars']:
            del result['inst_vars']

        if (
            result['type'] in (
                'nil', 'true', 'false', 'fixnum', 'array', 'float', 'string'
            )
            and 'module_ext' not in result and 'inst_vars' not in result
        ):
            actual_result = result['value']
        else:
            actual_result = result

        return actual_result

@dataclass(eq=False)
class True_(NodeData):
    TYPE_CODE = 'T'

@dataclass(eq=False)
class False_(NodeData):
    TYPE_CODE = 'F'

@dataclass(eq=False)
class Nil(NodeData):
    TYPE_CODE = '0'

@dataclass(eq=False)
class Fixnum(NodeData):
    TYPE_CODE = 'i'

    value: int

@dataclass(eq=False)
class Symbol(NodeData):
    TYPE_CODE = ':'

    text: bytes

@dataclass(eq=False)
class SymbolRef(NodeData):
    TYPE_CODE = ';'

    value: int

@dataclass(eq=False)
class ObjectRef(NodeData):
    TYPE_CODE = '@'

    value: int

@dataclass(eq=False)
class InstVars(NodeData):
    TYPE_CODE = 'I'

    child: Node
    members_list: list[tuple[Node, Node]]

    @property
    def members(self) -> dict[str, Node]:
        return {name.symbol_text: value for name, value in self.members_list}

@dataclass(eq=False)
class ModuleExt(NodeData):
    TYPE_CODE = 'e'

    module_node: Node
    child: Node

    @property
    def module_name(self) -> str:
        return self.module_node.symbol_text

@dataclass(eq=False)
class Array(NodeData):
    TYPE_CODE = '['

    items: list['Node']

@dataclass(eq=False)
class Bignum(NodeData):
    TYPE_CODE = 'l'

    value: int

@dataclass(eq=False)
class ClassRef(NodeData):
    TYPE_CODE = 'c'

    text: bytes

@dataclass(eq=False)
class ModuleRef(NodeData):
    TYPE_CODE = 'm'

    text: bytes

@dataclass(eq=False)
class ClassOrModuleRef(NodeData):
    TYPE_CODE = 'M'

    text: bytes

@dataclass(eq=False)
class Data(NodeData):
    TYPE_CODE = 'd'

    class_node: Node
    state: Node

    @property
    def class_name(self) -> str:
        return self.class_node.symbol_text

@dataclass(eq=False)
class Float(NodeData):
    TYPE_CODE = 'f'

    value: float

@dataclass(eq=False)
class Hash(NodeData):
    TYPE_CODE = '{'
    
    items: list[tuple[Node, Node]]

@dataclass(eq=False)
class DefaultHash(NodeData):
    TYPE_CODE = '}'
    
    items: list[tuple[Node, Node]]
    default: Node

@dataclass(eq=False)
class Object(NodeData):
    TYPE_CODE = 'o'

    class_node: Node
    members_list: list[tuple[Node, Node]]

    @property
    def class_name(self) -> str:
        return self.class_node.symbol_text

    @property
    def members(self) -> dict[str, Node]:
        return {name.symbol_text: value for name, value in self.members_list}

@dataclass(eq=False)
class Regex(NodeData):
    TYPE_CODE = '/'
    REGEX_OPTIONS = [re.I, re.X, re.M]

    text: bytes
    options_byte: int

    @property
    def options(self) -> set[re.RegexFlag]:
        result = set()
        bits = self.options_byte

        for i in range(8):
            bits, is_set = divmod(bits, 2)
            
            if is_set:
                try:
                    option = self.REGEX_OPTIONS[i]
                except IndexError:
                    raise DataError(
                        f"regex options byte (value {bits}) has {i}th bit set "
                        "but this does not correspond to a recognized option"
                    )
                else:
                    result.add(option)

        return result

@dataclass(eq=False)
class String(NodeData):
    TYPE_CODE = '"'

    text: bytes

@dataclass(eq=False)
class Struct(NodeData):
    TYPE_CODE = 'S'

    class_node: Node
    members_list: list[tuple[Node, Node]]

    @property
    def class_name(self) -> str:
        return self.class_node.symbol_text

    @property
    def members(self) -> dict[str, Node]:
        return {name.symbol_text: value for name, value in self.members_list}

@dataclass(eq=False)
class UserClass(NodeData):
    TYPE_CODE = 'C'

    class_node: Node
    child: Node

    @property
    def class_name(self) -> str:
        return self.class_node.symbol_text

@dataclass(eq=False)
class UserData(NodeData):
    TYPE_CODE = 'u'
    
    class_node: Node
    data: bytes

    @property
    def class_name(self) -> str:
        return self.class_node.symbol_text

@dataclass(eq=False)
class UserObject(NodeData):
    TYPE_CODE = 'U'

    class_node: Node
    child: Node

    @property
    def class_name(self) -> str:
        return self.class_node.symbol_text


class ParserError(Exception):
    pass

@dataclass
class Parser:
    stream: io.IOBase
    result: MarshalFile=field(default_factory=lambda: MarshalFile())

    def offset(self) -> int:
        return self.stream.tell()

    def read_bytes(self, count: int) -> bytes:
        result = self.stream.read(count)

        if len(result) < count:
            raise ParserError(
                f'unexpected end of input at offset {self.offset()}'
            )

        return result

    def read_byte(self) -> int:
        return self.read_bytes(1)[0]

    def read_file(self) -> MarshalFile:
        version = MarshalVersion(*self.read_bytes(2))

        if not version.is_supported():
            warn(
                f"version is {version}; only versions up to 4.8 are explicitly "
                "supported"
            )

        self.result.version = version
        self.result.content = self.read_object()

        if self.stream.read(1):
            warn(
                f"finished parsing at offset {self.offset()}, but the input "
                "file does not end here"
            )

        return self.result

    def read_object(self) -> Node:
        code = chr(self.read_byte())
        content: NodeData

        match code:
            case 'T':
                content = True_()
            case 'F':
                content = False_()
            case '0':
                content = Nil()
            case 'i':
                content = Fixnum(self.read_long())
            case ':':
                content = Symbol(self.read_byte_seq())
            case ';':
                content = SymbolRef(self.read_long())
            case '@':
                content = ObjectRef(self.read_long())
            case 'I':
                content = self.read_object_with_inst_vars()
            case 'e':
                content = self.read_object_with_module_ext()
            case '[':
                content = self.read_array()
            case 'l':
                content = self.read_bignum()
            case 'c':
                content = ClassRef(self.read_byte_seq())
            case 'm':
                content = ModuleRef(self.read_byte_seq())
            case 'M':
                content = ClassOrModuleRef(self.read_byte_seq())
            case 'd':
                content = self.read_data()
            case 'f':
                content = self.read_float()
            case '{':
                content = self.read_hash()
            case '}':
                content = self.read_default_hash()
            case 'o':
                content = self.read_gen_object()
            case '/':
                content = self.read_regex()
            case '"':
                content = String(self.read_byte_seq())
            case 'S':
                content = self.read_struct()
            case 'C':
                content = self.read_user_class()
            case 'u':
                content = self.read_user_data()
            case 'U':
                content = self.read_user_object()
            case _:
                raise ParserError(
                    f"unrecognized object type code '{code}' at offset "
                    f"{self.offset()}"
                )

        return Node(self.result, content)

    def read_long(self) -> int:
        head = int.from_bytes(self.read_bytes(1), 'little', signed=True)
    
        if not head:
            return 0
        
        head_abs = abs(head)
        sign = head // abs(head)        
        
        if head_abs >= 5:
            return sign * (head_abs - 5)
        
        body = int.from_bytes(self.read_bytes(head_abs), 'little')
    
        if sign < 0:
            body -= 2 ** (8 * head_abs)
        
        return body

    def read_byte_seq(self) -> bytes:
        length = self.read_long()
        return self.read_bytes(length)

    def read_key_value_pairs(self) -> list[tuple[Node, Node]]:
        length = self.read_long()
        result: list[tuple[Node, Node]] = []

        for _ in range(length):
            name = self.read_object()
            value = self.read_object()
            result.append((name, value))

        return result

    def read_object_with_inst_vars(self) -> InstVars:
        child = self.read_object()
        inst_vars = self.read_key_value_pairs()
        return InstVars(child, inst_vars)

    def read_object_with_module_ext(self) -> ModuleExt:
        module = self.read_object()
        child = self.read_object()
        return ModuleExt(module, child)

    def read_array(self) -> Array:
        length = self.read_long()
        return Array([self.read_object() for _ in range(length)])

    def read_bignum(self) -> Bignum:
        sign_code = chr(self.read_byte())
        
        try:
            sign = {'+': 1, '-': -1}[sign_code]
        except KeyError:
            raise ParserError(
                f'unrecognized bignum sign code {sign_code} at offset '
                f'{self.offset()}'
            )

        len_in_words = self.read_long()
        len_in_bytes = len_in_words * 2
        body = self.read_bytes(len_in_bytes)
        value = sign * int.from_bytes(body, 'little')
        return Bignum(value)

    def read_data(self) -> Data:
        klass = self.read_object()
        state = self.read_object()
        return Data(klass, state)

    def read_float(self) -> Float:
        s = self.read_byte_seq().decode('latin-1')
        
        try:
            value = {'inf': math.inf, '-inf': -math.inf, 'nan': math.nan}[s]
        except KeyError:
            point = locale.localeconv()['decimal_point']
            assert isinstance(point, str) # for mypy
            point = '\\' + point
            decimal_exp_pat = r'[Ee][+-]?\d+'
            decimal_pat = fr'\d*(?:{point}\d*)?(?:{decimal_exp_pat})?'
            bin_exp_pat = r'[Pp][+-]?\d+'
            hex_pat = fr'(0[xX])[\da-fA-F]+(?:{point}[\da-fA-F]*)?(?:{bin_exp_pat})?'
            m = re.match(fr'^\s*[+-]?(?:{hex_pat}|{decimal_pat})', s)
            assert m is not None
            s, is_hex = m.group(0, 1)

            if not s:
                value = 0.0
            elif is_hex:
                s = locale.delocalize(s)
                value = float.fromhex(s)
            else:
                value = locale.atof(s)

        return Float(value)

    def read_hash(self) -> Hash:
        result = self.read_key_value_pairs()
        return Hash(result)

    def read_default_hash(self) -> DefaultHash:
        items = self.read_key_value_pairs()
        default = self.read_object()
        return DefaultHash(items, default)

    def read_gen_object(self) -> Object:
        klass = self.read_object()
        inst_vars = self.read_key_value_pairs()
        return Object(klass, inst_vars)

    def read_regex(self) -> Regex:
        source = self.read_byte_seq()
        options_byte = self.read_byte()
        return Regex(source, options_byte)

    def read_struct(self) -> Struct:
        klass = self.read_object()
        members = self.read_key_value_pairs()
        return Struct(klass, members)

    def read_user_class(self) -> UserClass:
        klass = self.read_object()
        child = self.read_object()
        return UserClass(klass, child)

    def read_user_data(self) -> UserData:
        klass = self.read_object()
        data = self.read_byte_seq()
        return UserData(klass, data)

    def read_user_object(self) -> UserObject:
        klass = self.read_object()
        child = self.read_object()
        return UserObject(klass, child)

def parse_stream(stream: io.IOBase) -> MarshalFile:
    parser = Parser(stream)
    return parser.read_file()

def parse_file(path: Path) -> MarshalFile:
    with path.open('rb') as f:
        return parse_stream(f)
