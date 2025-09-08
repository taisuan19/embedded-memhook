# Embedded Memhook

Utilities and hooks for tracking memory usage and leaks. The project is split into
separate modules so it can be adapted for embedded environments.

## Layout

- `leakhook/` – LD_PRELOAD library that intercepts malloc/free on Linux.
- `memhook_toolkit/` – tools to decode and analyse memory trace logs.
- `embedded/` – placeholder for upcoming embedded malloc/free hooks.

## Build

```bash
# build LD_PRELOAD hook
make -C leakhook

# build log analysis tools
make -C memhook_toolkit
```

The leakhook build outputs `libleakhook.so` and the toolkit produces binaries under
`memhook_toolkit/bin/`.

## Embedded hooks

Code for intercepting allocators on embedded targets will live under `embedded/`.
This is currently a stub so that platform specific implementations can be added later.
