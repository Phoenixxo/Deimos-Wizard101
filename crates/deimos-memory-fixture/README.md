# Deimos memory fixture

This Windows-only process provides deterministic memory for integration tests
without launching Wizard101.

At startup it allocates one `PAGE_READONLY` region and one `PAGE_READWRITE`
region, initializes known primitive values and a two-hop pointer chain, then
publishes one line of runtime JSON:

```text
DEIMOS_MEMORY_FIXTURE={...}
```

The metadata contains the process ID, runtime region addresses, field offsets,
exact and wildcard signatures, expected bytes, pointer-chain offsets, region
protections, and lifecycle contract. Consumers must use this metadata or scan
the published signatures; addresses are intentionally allocated at runtime and
must never be hardcoded.

For a pointer chain, start at the named root-pattern match. Add and dereference
each offset covered by `dereference_count`, then add the final offset to reach
the target value.

Send a line containing `shutdown` on stdin to stop the fixture. Closing stdin
also stops it. A clean shutdown prints:

```text
DEIMOS_MEMORY_FIXTURE_STOPPED
```

The read/write region exists so future mutation scenarios can use the same
fixture, but metadata declares `mutation_enabled: false`. Tests open the process
with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` only. Write behavior remains
out of scope until DMS-014.
