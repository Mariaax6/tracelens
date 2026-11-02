# Contributing

Thanks for helping! The project deliberately has **no runtime or test dependencies**, so it builds offline with just a JDK 17+.

## Build and test

```sh
sh build.sh   # compile, run unit tests, package dist/tracelens.jar
sh demo.sh    # run the examples and verify exit codes and counts
```

On Windows use `.\build.ps1` and `.\demo.ps1`.

## Changing the decoder or the detection rule

1. Build synthetic frames with `test/.../Fixtures.java`; never add real captures to the repository.
2. Add tests for the accepted case and for the malformed or boundary cases next to it.
3. Keep the invariant that every record lands in exactly one coverage category.
4. If you change an example capture, regenerate all of them with `Fixtures` (the tests require byte-identical files) and update the counts in the README, `demo.sh` and `demo.ps1`.
5. Add a line to `CHANGELOG.md`.

## Principles

- Offline and read-only: no live capture, sockets or command execution.
- Never turn unsupported or malformed traffic into flows; count it instead.
- An alert is a lead, not a verdict; do not claim detection accuracy that has not been measured.
