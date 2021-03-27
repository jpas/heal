# HEAL

HEAL is a Homomorphic Encryption Adapter Library.

## Goal

To serve as a straitforward, lightweight, and reasonably typed [lingua fanca]
for homomorphic encryption libraries. To this end, we base our interface on the
plaintext domains that can be used for homomorphic computations.

| Plaintext                   | BFV | BGV | CKKS | TFHE | Concrete |
|:----------------------------|:----|:----|:-----|:-----|:---------|
| Booleans                    | +v  | +v  |      | +v?  |          |
| Integers mod p              | +v  | +v  |      |      |          |
| "Big" integers              | +   | ?   |      |      |          |
| Approximate real numbers    | +   |     | +v   |      | +v       |
| Approximate complex numbers |     |     | +v   |      |          |

## Buidling

HEAL depends on:
- [Microsoft SEAL]
- [PALISADE] -- planned
- [HElib] -- planned

Version information can be found in [CMakeLists.txt](./CMakeLists.txt).

[Microsoft SEAL]: https://sealcrypto.org/
[PALISADE]: https://palisade-crypto.org/
[HElib]: https://homenc.github.io/HElib/

Somtime in the future, we may automatically detect which backends are available
at runtime. But currently we require the all backends present.

HEAL can built built with:
- [CMake](), or
- `nix-build` if the [nix] package manager is available, or
- `nix build .` if you use [nix flakes] with 
- [`nix`]() via flakes, or
- [`nix-build`]()

To build with CMake:
```
$ cmake -S . -B build # setup
$ cmake --build build # build
```

To build with `nix`:
```
$ nix build .
```
