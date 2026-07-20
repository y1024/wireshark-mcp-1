# Security notes

- Capture only traffic you are **authorized** to inspect.
- Treat pcaps and verbose dumps as sensitive; redact secrets before sharing.
- Interface names are allowlisted against `tshark -D` and rejected if they contain shell metacharacters.
- All TShark invocations use argv lists with `shell=False` (no shell interpolation).
- Failed captures return **errors**, never fabricated / simulated packets.
- Prefer short captures and display filters that limit sensitive payloads.
