#!/bin/bash
# Generate QEMU instruction trace for ARM64 programs

set -e

PROGRAM="${1}"
OUTPUT="${2:-trace.log}"

if [ -z "$PROGRAM" ]; then
    echo "Usage: $0 <arm64_program> [output_file]"
    echo ""
    echo "Example:"
    echo "  $0 ./my_program trace.log"
    echo ""
    echo "This will generate an instruction trace using QEMU's -d in_asm option."
    exit 1
fi

if [ ! -f "$PROGRAM" ]; then
    echo "Error: Program file '$PROGRAM' not found"
    exit 1
fi

# Check if qemu-aarch64-static is available
if ! command -v qemu-aarch64-static &> /dev/null; then
    echo "Error: qemu-aarch64-static not found"
    echo "Please install: sudo apt-get install qemu-user-static"
    exit 1
fi

echo "Generating trace for: $PROGRAM"
echo "Output file: $OUTPUT"
echo ""

# Run QEMU with instruction + register state trace
qemu-aarch64-static -one-insn-per-tb -d in_asm,exec,cpu,nochain -D "$OUTPUT" "$PROGRAM"

echo ""
echo "Trace generated successfully!"
echo "File size: $(du -h "$OUTPUT" | cut -f1)"
echo "Lines: $(wc -l < "$OUTPUT")"
echo ""
echo "To import into database:"
echo "  python examples/qemu_import_example.py"
