# purescript-cardano-serialization-lib

This is a code-generated wrapper for `@mlabs-haskell/cardano-serialization-lib-gc`, a vendored version of [CSL by Emurgo](https://github.com/Emurgo/cardano-serialization-lib/).

## How to use the library

Most likely you would want to use [`purescript-cardano-types`](https://github.com/mlabs-haskell/purescript-cardano-types) - that library provides a nice purely-functional interface on top of these raw bindings.

## How this library works

Library ports the [CSL api](https://github.com/Emurgo/cardano-serialization-lib/blob/master/rust/pkg/cardano_serialization_lib.js.flow).
The JS classes are converted to values of record type which
define interface for a given class. The value contains both static and object
methods. For object methods the self argument always goes first.

For example if we want to create `BigNum` from string in JS we can write:

```js
Csl.BigNum.from_str("100200");
```

In purescript it is called on the value `bigInt` which provides the function:

```purescript
import Cardano.Serialization.Lib as CSL

CSL.bigNum_fromStr "100200"
```

### How to build your code with it

To use this library you whould also add `@mlabs-haskell/cardano-serialization-lib-gc`
as external dependency. Provide this library with your JS code package manager
and also compile the purs code with it as external dep.

Usage example: [`purescript-cardano-types`](https://github.com/mlabs-haskell/purescript-cardano-types).

## Possible issues

Code is auto generated from CSL API.
Alas for some functions it's not possible to tell is it pure
or dirty. Submit an issue if you have found an effectful function
which is declared like pure and vise versa.

See the `code-gen` directory for the source code of the code parser and generator.

## How to run the code-gen:

1. Run the haskell binary:

```bash
cd code-gen/parse-csl
make run # assumes haskell stack is installed
```

2. Copy the output

```bash
make copy # run in the project root
```

3. Apply formatting

```bash
make format # run in the project root
```

## How the codegen pipeline works

1. `./code-gen/parse-csl/fixtures` contains some fixture files that the haskell binary reads
2. `./code-gen/parse-csl/data` contains type definitions for CSL, based on which the PS code is generated
3. `./code-gen/parse-csl/output` is where the generated files appear, from where they can be copied to `src/`
