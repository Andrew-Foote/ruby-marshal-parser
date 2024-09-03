# iddain't preddy, buddit does the jawb

from abc import ABC, ABCMeta
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
import io
import json
import locale
import math
from pathlib import Path
import re
import sys
from warnings import warn

class MarshalObject(ABC):
    pass

@dataclass
class MarshalVersion:
    major: int
    minor: int

    def __str__(self) -> str:
        return f'{self.major}.{self.minor}'
    
    def is_supported(self):
        return (self.major, self.minor) <= (4, 8)

class MarshalNonToplevelObject(MarshalObject, metaclass=ABCMeta):
    pass

class MarshalNonRefObject(MarshalObject, metaclass=ABCMeta):
    pass

@dataclass
class MarshalFile(MarshalNonRefObject):
    version: MarshalVersion
    root: MarshalObject

@dataclass(eq=False)
class MarshalNil(MarshalNonToplevelObject, MarshalNonRefObject):
    pass

@dataclass(eq=False)
class MarshalTrue(MarshalNonToplevelObject, MarshalNonRefObject):
    pass

@dataclass(eq=False)
class MarshalFalse(MarshalNonToplevelObject, MarshalNonRefObject):
    pass

@dataclass(eq=False)
class MarshalFixnum(MarshalNonToplevelObject, MarshalNonRefObject):
    value: int

@dataclass(eq=False)
class MarshalSymbol(MarshalNonToplevelObject, MarshalNonRefObject):
    name: bytes

@dataclass(eq=False)
class MarshalSymbolRef(MarshalNonToplevelObject):
    value: int

@dataclass(eq=False)
class MarshalObjectRef(MarshalNonToplevelObject):
    value: int

MarshalAlist = list[tuple['MarshalNonToplevelObject', 'MarshalNonToplevelObject']]

@dataclass(eq=False)
class MarshalInstVars(MarshalNonToplevelObject, MarshalNonRefObject):
    obj: 'MarshalObject'
    inst_vars: MarshalAlist

@dataclass(eq=False)
class MarshalModuleExt(MarshalNonToplevelObject, MarshalNonRefObject):
    module: 'MarshalObject'
    obj: 'MarshalObject'

@dataclass(eq=False)
class MarshalArray(MarshalNonToplevelObject, MarshalNonRefObject):
    items: list['MarshalNonToplevelObject']

@dataclass(eq=False)
class MarshalBignum(MarshalNonToplevelObject, MarshalNonRefObject):
    value: int

@dataclass(eq=False)
class MarshalClassRef(MarshalNonToplevelObject, MarshalNonRefObject):
    name: bytes

@dataclass(eq=False)
class MarshalModuleRef(MarshalNonToplevelObject, MarshalNonRefObject):
    name: bytes

@dataclass(eq=False)
class MarshalClassOrModuleRef(MarshalNonToplevelObject, MarshalNonRefObject):
    name: bytes

@dataclass(eq=False)
class MarshalData(MarshalNonToplevelObject, MarshalNonRefObject):
    class_ref: 'MarshalObject'
    state: 'MarshalObject'

@dataclass(eq=False)
class MarshalFloat(MarshalNonToplevelObject, MarshalNonRefObject):
    value: float

@dataclass(eq=False)
class MarshalHash(MarshalNonToplevelObject, MarshalNonRefObject):
    items: MarshalAlist

@dataclass(eq=False)
class MarshalDefaultHash(MarshalNonToplevelObject, MarshalNonRefObject):
    items: MarshalAlist
    default: 'MarshalObject'

@dataclass(eq=False)
class MarshalGenObject(MarshalNonToplevelObject, MarshalNonRefObject):
    class_ref: 'MarshalObject'
    inst_vars: MarshalAlist

@dataclass(eq=False)
class MarshalRegex(MarshalNonToplevelObject, MarshalNonRefObject):
    source: bytes
    options: set[re.RegexFlag]

@dataclass(eq=False)
class MarshalString(MarshalNonToplevelObject, MarshalNonRefObject):
    value: bytes

@dataclass(eq=False)
class MarshalStruct(MarshalNonToplevelObject, MarshalNonRefObject):
    class_ref: 'MarshalObject'
    members: MarshalAlist

@dataclass(eq=False)
class MarshalUserClass(MarshalNonToplevelObject, MarshalNonRefObject):
    class_ref: 'MarshalObject'
    obj: 'MarshalObject'

@dataclass(eq=False)
class MarshalUserData(MarshalNonToplevelObject, MarshalNonRefObject):
    class_ref: 'MarshalObject'
    data: bytes

@dataclass(eq=False)
class MarshalUserObject(MarshalNonToplevelObject, MarshalNonRefObject):
    class_ref: 'MarshalObject'
    obj: 'MarshalObject'

class ParserError(ValueError):
    pass

@dataclass
class Parser:
    stream: io.BufferedIOBase

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

        root = self.read_object()

        if self.stream.read1():
            warn(
                f"finished parsing at offset {self.offset()}, but the input "
                "file does not end here"
            )

        return MarshalFile(version, root)

    def read_object(self) -> MarshalNonToplevelObject:
        code = chr(self.read_byte())
        
        match code:
            case '0':
                return MarshalNil()
            case 'T':
                return MarshalTrue()
            case 'F':
                return MarshalFalse()
            case 'i':
                return MarshalFixnum(self.read_long())
            case ':':
                return MarshalSymbol(self.read_byte_seq())
            case ';':
                return MarshalSymbolRef(self.read_long())
            case '@':
                return MarshalObjectRef(self.read_long())
            case 'I':
                return self.read_object_with_inst_vars()
            case 'e':
                return self.read_object_with_module_ext()
            case '[':
                return self.read_array()
            case 'l':
                return self.read_bignum()
            case 'c':
                return MarshalClassRef(self.read_byte_seq())
            case 'm':
                return MarshalModuleRef(self.read_byte_seq())
            case 'M':
                return MarshalClassOrModuleRef(self.read_byte_seq())
            case 'd':
                return self.read_data()
            case 'f':
                return self.read_float()
            case '{':
                return self.read_hash()
            case '}':
                return self.read_default_hash()
            case 'o':
                return self.read_gen_object()
            case '/':
                return self.read_regex()
            case '"':
                return MarshalString(self.read_byte_seq())
            case 'S':
                return self.read_struct()
            case 'C':
                return self.read_user_class()
            case 'u':
                return self.read_user_data()
            case 'U':
                return self.read_user_object()
            case _:
                raise ParserError(
                    f"unrecognized object type code '{code}' at offset "
                    f"{self.offset()}"
                )

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

    def read_symbol_or_symbol_ref(self) -> MarshalNonToplevelObject:
        result = self.read_object()

        if not (
            isinstance(result, MarshalSymbol)
            or isinstance(result, MarshalSymbolRef)
        ):
            warn(
                f"got an object of type '{type(result).__name__}' at offset "
                f"{self.offset()}, but expected one of type 'MarshalSymbol' or"
                "'MarshalSymbolRef'"
            )

        return result

    def read_inst_vars(self) -> MarshalAlist:
        length = self.read_long()
        result = []

        for _ in range(length):
            name = self.read_symbol_or_symbol_ref()
            value = self.read_object()
            result.append((name, value))

        return result

    def read_object_with_inst_vars(self) -> MarshalInstVars:
        obj = self.read_object()
        inst_vars = self.read_inst_vars()
        return MarshalInstVars(obj, inst_vars)

    def read_object_with_module_ext(self) -> MarshalModuleExt:
        module_ref = self.read_symbol_or_symbol_ref()
        obj = self.read_object()
        return MarshalModuleExt(module_ref, obj)

    def read_array(self) -> MarshalArray:
        length = self.read_long()
        result = []
        
        for _ in range(length):
            result.append(self.read_object())

        return MarshalArray(result)

    def read_bignum(self) -> MarshalBignum:
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
        return MarshalBignum(value)

    def read_data(self) -> MarshalData:
        class_ref = self.read_symbol_or_symbol_ref()
        state = self.read_object()
        return MarshalData(class_ref, state)

    def read_float(self) -> MarshalFloat:
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

        return MarshalFloat(value)

    def read_hash(self) -> MarshalHash:
        length = self.read_long()
        result = []

        for _ in range(length):
            key = self.read_object()
            value = self.read_object()
            result.append((key, value))

        return MarshalHash(result)

    def read_default_hash(self) -> MarshalDefaultHash:
        base = self.read_hash()
        default = self.read_object()
        return MarshalDefaultHash(base.items, default)

    def read_gen_object(self) -> MarshalGenObject:
        class_ref = self.read_symbol_or_symbol_ref()
        inst_vars = self.read_inst_vars()
        return MarshalGenObject(class_ref, inst_vars)

    REGEX_OPTIONS = [re.I, re.X, re.M]

    def read_regex(self) -> MarshalRegex:
        source = self.read_byte_seq()
        bits = self.read_byte()
        options = set()

        for i in range(8):
            bits, is_set = divmod(bits, 2)
            
            if is_set:
                try:
                    option = self.REGEX_OPTIONS[i]
                except IndexError:
                    warn(
                        f"at offset {self.offset()}, regex options byte (value "
                        f"{bits}) has {i}th bit set but this does not "
                        "correspond to a recognized option"
                    )
                else:
                    options.add(option)

        return MarshalRegex(source, options)

    def read_struct(self) -> MarshalStruct:
        class_ref = self.read_symbol_or_symbol_ref()
        members = self.read_inst_vars()
        return MarshalStruct(class_ref, members)

    def read_user_class(self) -> MarshalUserClass:
        class_ref = self.read_symbol_or_symbol_ref()
        obj = self.read_object()
        return MarshalUserClass(class_ref, obj)

    def read_user_data(self) -> MarshalUserData:
        class_ref = self.read_symbol_or_symbol_ref()
        data = self.read_byte_seq()
        return MarshalUserData(class_ref, data)

    def read_user_object(self) -> MarshalUserObject:
        class_ref = self.read_symbol_or_symbol_ref()
        obj = self.read_object()
        return MarshalUserObject(class_ref, obj)

def parse_stream(stream: io.BufferedIOBase) -> MarshalFile:
    parser = Parser(stream)
    return parser.read_file()

def parse_file(path: Path) -> MarshalFile:
    with path.open('rb') as f:
        return parse_stream(f)

def parse_bytes(content: bytes) -> MarshalFile:
    return parse_stream(io.BytesIO(content))

def marshal_object_can_be_object_ref_target(obj: MarshalObject) -> bool:
    return isinstance(obj, (
        MarshalArray, MarshalBignum, MarshalClassRef, MarshalModuleRef,
        MarshalClassOrModuleRef, MarshalData, MarshalFloat, MarshalHash,
        MarshalDefaultHash, MarshalGenObject, MarshalRegex, MarshalString,
        MarshalStruct, MarshalUserClass, MarshalUserData, MarshalUserObject
    ))

def marshal_object_can_have_children(obj: MarshalObject) -> bool:
    return isinstance(obj, (
        MarshalArray, MarshalData, MarshalHash, MarshalDefaultHash, 
        MarshalGenObject, MarshalStruct, MarshalUserClass, MarshalUserData,
        MarshalUserObject
    ))

class CyclicRefHandler(Enum):
    IGNORE = 0
    FAIL = 1

def expand_refs(
    obj: MarshalObject, *,
    cyclic_ref_handler: CyclicRefHandler=CyclicRefHandler.IGNORE,
    symbols: list[MarshalSymbol | None] | None=None,
    objects: list[MarshalNonRefObject | None] | None=None,
    parents: set[int] | None=None,
    keep_parent_id: bool=False
) -> MarshalObject:
    
    if symbols is None:
        symbols = []

    if objects is None:
        objects = []

    if parents is None:
        parents = set()

    def recurse(obj, keep_parent_id=False):
        return expand_refs(
            obj,
            cyclic_ref_handler=cyclic_ref_handler,
            symbols=symbols,
            objects=objects,
            parents=parents,
            keep_parent_id=keep_parent_id
        )

    if isinstance(obj, MarshalSymbol):
        symbol_id = len(symbols)
        symbols.append(obj)
    elif marshal_object_can_be_object_ref_target(obj):
        object_id = len(objects)
        objects.append(None)

        if marshal_object_can_have_children(obj):
            parents.add(object_id)

    result: MarshalObject

    match obj:
        case MarshalFile(version, root):
            result = MarshalFile(version, recurse(root))
        case MarshalSymbolRef(obj_id):
            symbol = symbols[obj_id]
            assert symbol is not None
            result = symbol
        case MarshalObjectRef(obj_id):
            if obj_id in parents:
                assert objects[obj_id] is None
                match cyclic_ref_handler:
                    case CyclicRefHandler.IGNORE:
                        result = obj
                    case CyclicRefHandler.FAIL:
                        raise ParserError(f"cyclic reference to ID {obj_id}")
            else:
                deref = objects[obj_id]
                assert deref is not None
                result = deref
        case MarshalInstVars(obj, inst_vars):
            object_id = len(objects)
            obj_result = recurse(obj, keep_parent_id=True)
            new_inst_vars = []

            for name, value in inst_vars:
                new_inst_vars.append((recurse(name), recurse(value)))

            result = MarshalInstVars(obj_result, new_inst_vars)

            if marshal_object_can_be_object_ref_target(obj):
                objects[object_id] = result

            if marshal_object_can_have_children(obj):
                parents.remove(object_id)
        case MarshalModuleExt(module_ref, obj):
            object_id = len(objects)
            result = MarshalModuleExt(recurse(module_ref), recurse(obj))

            if marshal_object_can_be_object_ref_target(obj):
                objects[object_id] = result
        case MarshalArray(items):
            result = MarshalArray(list(map(recurse, items)))
        case MarshalData(class_ref, state):
            result = MarshalData(recurse(class_ref), recurse(state))
        case MarshalHash(items):
            new_items = []

            for key, value in items:
                new_items.append((recurse(key), recurse(value)))

            result = MarshalHash(new_items)
        case MarshalDefaultHash(items, default):
            new_items = []

            for key, value in items:
                new_items.append((recurse(key), recurse(value)))

            result = MarshalDefaultHash(new_items, recurse(default))
        case MarshalGenObject(class_ref, inst_vars):
            class_ref = recurse(class_ref)
            new_inst_vars = []

            for name, value in inst_vars:
                new_inst_vars.append((recurse(name), recurse(value)))

            result = MarshalGenObject(class_ref, new_inst_vars)
        case MarshalStruct(class_ref, members):
            class_ref = recurse(class_ref)
            new_members = []

            for name, value in members:
                new_members.append((recurse(name), recurse(value)))

            result = MarshalStruct(class_ref, new_members)
        case MarshalUserClass(class_ref, obj):
            result = MarshalUserClass(recurse(class_ref), recurse(obj))
        case MarshalUserData(class_ref, data):
            result = MarshalUserData(recurse(class_ref), data)
        case MarshalUserObject(class_ref, obj):
            result = MarshalUserObject(recurse(class_ref), recurse(obj))
        case _:
            result = obj
    
    if marshal_object_can_be_object_ref_target(obj):
        if marshal_object_can_have_children(obj) and not keep_parent_id:
            parents.remove(object_id)

        assert isinstance(result, MarshalNonRefObject)
        objects[object_id] = result

    return result

# compress module ext and inst vars into one

@dataclass
class Options:
    distinguish_bignums: bool=False
    distinguish_symbols: bool=False
    preserve_inst_var_order: bool=False
    preserve_cyclic_refs: bool=False
    preserve_refs: bool=False # implies preserve_cyclic_refs
    preserve_encodings: bool=False

JsonDumpable = (
    None | bool | int | float | str
    | list['JsonDumpable']
    | tuple['JsonDumpable', ...]
    | dict[str, 'JsonDumpable']
)

def interpret_marshal_object_as_encoding(obj: MarshalObject) -> str:
    match obj:
        case MarshalTrue():
            return 'utf-8'
        case MarshalFalse():
            return 'us-ascii'
        case MarshalString(value):
            # hopefully the ruby strings and the python strings are compatible
            try:
                b'\x00'.decode(value)
            except LookupError:
                raise ParserError(f"Ruby encoding string '{value}' is not understood by Python")

            return value
        case _:
            raise ParserError(f"object {obj} can't be interpreted as an encoding")

def to_json_dumpable_without_expanding_refs(
    obj: MarshalObject, options: Options, encoding: str | None=None
) -> JsonDumpable:

    def recurse(obj: MarshalObject, encoding: str | None=None) -> JsonDumpable:
        return to_json_dumpable_without_expanding_refs(obj, options, encoding)

    match obj:
        case MarshalFile(version, root):
            return {'version': str(version), 'root': recurse(root)}
        case MarshalNil():
            return None
        case MarshalTrue():
            return True
        case MarshalFalse():
            return False
        case MarshalFixnum(value):
            return value
        case MarshalSymbol(name):
            if encoding is None:
                result = name.decode('utf-8', 'surrogateescape')
            else:
                result = name.decode(encoding)

            if options.distinguish_symbols:
                return {
                    'type': 'symbol',
                    'name': result
                }
            else:
                return result
        case MarshalSymbolRef(value):
            return {'type': 'symbol-ref', 'value': value}
        case MarshalObjectRef(value):
            return {'type': 'object-ref', 'value': value}
        case MarshalInstVars(obj, inst_vars):
            if not options.preserve_encodings:
                new_inst_vars = []

                for name, value in inst_vars:
                    match name:
                        case MarshalSymbol(b'E'):
                            encoding = interpret_marshal_object_as_encoding(value)
                        case _:
                            new_inst_vars.append((name, value))

                inst_vars = new_inst_vars

            if not inst_vars:
                return recurse(obj, encoding)

            if options.preserve_inst_var_order:
                inst_vars = [
                    (recurse(name), recurse(value))
                    for name, value in inst_vars
                ]
            else:
                inst_vars = {
                    recurse(name): recurse(value) for name, value in inst_vars
                }

            return {
                'type': 'inst-vars',
                'base': recurse(obj, encoding),
                'inst_vars': inst_vars
            }
        case MarshalModuleExt(module_ref, obj):
            return {
                'type': 'module-ext',
                'module': recurse(module_ref),
                'base': recurse(obj)
            }
        case MarshalArray(items):
            return [recurse(item) for item in items]
        case MarshalBignum(value):
            if options.distinguish_bignums:
                return {'type': 'bignum', 'value': value}
            else:
                return value
        case MarshalClassRef(name):
            return {'type': 'class-ref', 'value': name.decode('utf-8', 'surrogateescape')}
        case MarshalModuleRef(name):
            return {'type': 'module-ref', 'value': name.decode('utf-8', 'surrogateescape')}
        case MarshalClassOrModuleRef(name):
            return {'type': 'class-or-module-ref', 'value': name.decode('utf-8', 'surrogateescape')}
        case MarshalData(class_ref, state):
            return {
                'type': 'data', 
                'class': recurse(class_ref), 
                'state': recurse(state)
            }
        case MarshalFloat(value):
            return value
        case MarshalHash(items):
            return {
                'type': 'hash',
                'items': [
                    (recurse(key), recurse(value))
                    for key, value in items
                ]
            }
        case MarshalDefaultHash(items, default):
            return {
                'type': 'default-hash',
                'items': [
                    (recurse(key), recurse(value))
                    for key, value in items
                ],
                'default': recurse(default),
            }
        case MarshalGenObject(class_ref, inst_vars):
            if options.preserve_inst_var_order:
                inst_vars = [
                    (recurse(name), recurse(value))
                    for name, value in inst_vars
                ]
            else:
                inst_vars = {
                    recurse(name): recurse(value) for name, value in inst_vars
                }

            return {
                'type': 'gen-object',
                'class_ref': recurse(class_ref),
                'inst_vars': inst_vars
            }
        case MarshalRegex(source, regex_opts):
            if encoding is None:
                source = source.decode('utf-8', 'surrogateescape')
            else:
                source = source.decode(encoding)

            return {
                'type': 'regex',
                'source': source,
                'options': [option.name for option in sorted(regex_opts)]
            }
        case MarshalString(value):
            if encoding is None:
                return value.decode('utf-8', 'surrogateescape')
            else:
                return value.decode(encoding)
        case MarshalStruct(class_ref, members):
            if options.preserve_inst_var_order:
                members = [
                    (recurse(name), recurse(value))
                    for name, value in members
                ]
            else:
                members = {
                    recurse(name): recurse(value) for name, value in members
                }

            return {
                'type': 'struct',
                'class': recurse(class_ref),
                'members': members
            }
        case MarshalUserClass(class_ref, obj):
            return {
                'type': 'user-class',
                'class': recurse(class_ref),
                'base': recurse(obj)
            }
        case MarshalUserData(class_ref, data):
            return {
                'type': 'user-data',
                'class': recurse(class_ref),
                'data': data.decode('utf-8', 'surrogateescape')
            }
        case MarshalUserObject(class_ref, obj):
            return {
                'type': 'user-object',
                'class': recurse(class_ref),
                'base': recurse(obj)
            }
        case _:
            raise ValueError(
                f"cannot convert object of type '{type(obj).__name__}' to "
                "JsonDumpable"
            )

            return {}

def to_json_dumpable(obj: MarshalObject, options: Options) -> JsonDumpable:
    if not options.preserve_refs:
        obj = expand_refs(obj, cyclic_ref_handler=(
            CyclicRefHandler.IGNORE if options.preserve_cyclic_refs
            else CyclicRefHandler.FAIL
        ))

    return to_json_dumpable_without_expanding_refs(obj, options)

def to_json(obj: MarshalObject, options: Options) -> str:
    return json.dumps(to_json_dumpable(obj, options))

def main(
    input_file: Path, output_file: Path, *,
    overwrite: bool=False, distinguish_bignums: bool=False,
    distinguish_symbols: bool=False, preserve_cyclic_refs: bool=False,
    preserve_refs: bool=False, preserve_encodings: bool=False,
    preserve_inst_var_order: bool=False
) -> None:

    options = Options(
        distinguish_bignums=distinguish_bignums,
        distinguish_symbols=distinguish_symbols,
        preserve_cyclic_refs=preserve_cyclic_refs,
        preserve_refs=preserve_refs,
        preserve_encodings=preserve_encodings,
        preserve_inst_var_order=preserve_inst_var_order
    )

    parsed_content = parse_file(input_file)
    json_content = to_json(parsed_content, options)
    output_file = output_file.absolute()

    if not overwrite and output_file.exists():
        print(
            f'File "{output_file}" already exists. Use the -o option to overwrite '
            'existing files.'
        )
        
        sys.exit(1)

    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open('w') as ofh:
        ofh.write(json_content)

if __name__ == '__main__':
    import argparse

    arg_parser = argparse.ArgumentParser(
        prog='ruby_marshal_parser',
        description="Parses files produced by Ruby's Marshal.dump function."
    )

    arg_parser.add_argument('input_file', type=Path)
    arg_parser.add_argument('output_file', type=Path)

    arg_parser.add_argument('-o', '--overwrite', action='store_true', help=(
        'overwrite the output file if it already exists'
    ))

    arg_parser.add_argument(
        '-b', '--distinguish-bignums', action='store_true', help=(
            'preserve the distinction between fixnums and bignums in the output'
        )
    )

    arg_parser.add_argument(
        '-s', '--distinguish-symbols', action='store_true', help=(
            'preserve the distinction between strings and symbols in the output'
        )
    )
    
    arg_parser.add_argument(
        '-c', '--preserve-cyclic-refs', action='store_true', help=(
            'instead of raising an error when encountering an object '
            'reference that would result in a cycle, just don\'t expand those '
            'references'
        )
    )
    
    arg_parser.add_argument('-p', '--preserve-refs', action='store_true', help=(
        'don\'t expand symbol and object references at all'
    ))

    arg_parser.add_argument(
        '-e', '--preserve-encodings', action='store_true', help=(
            'don\'t decode symbols and strings using the encodings supplied via'
            'instance variables'
        )
    )

    arg_parser.add_argument(
        '-i', '--preserve-inst-var-order', action='store_true', help=(
            'encode instance variable lists as ordered lists of tuples rather '
            'than as dictionaries'
        )
    )

    parsed_args = arg_parser.parse_args()
    
    main(
        parsed_args.input_file, parsed_args.output_file,
        overwrite=parsed_args.overwrite,
        distinguish_bignums=parsed_args.distinguish_bignums,
        distinguish_symbols=parsed_args.distinguish_symbols,
        preserve_cyclic_refs=parsed_args.preserve_cyclic_refs,
        preserve_refs=parsed_args.preserve_refs,
        preserve_encodings=parsed_args.preserve_encodings,
        preserve_inst_var_order=parsed_args.preserve_inst_var_order
    )