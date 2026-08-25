# Protocol budgets

Canonical CBOR is the binary wire format; JSON is prohibited on the wire. v1 caps frames at 64 KiB, ordinary encrypted text at 4 KiB, and batches at 50 entries. Steady-state short content targets <=512 application bytes, warning above 1024 bytes. MLS welcomes/commits are measured separately. Compression is never automatic for small frames.
