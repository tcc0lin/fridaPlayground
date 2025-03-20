export function hex_dump(buffer: Buffer, maxLength = 512 * 10): string {
  let hex = "";
  let ascii = "";
  let output = "";
  let offset = 0;
  const truncated = buffer.length > maxLength;
  const displayBuffer = truncated ? buffer.slice(0, maxLength) : buffer;
  for (let i = 0; i < displayBuffer.length; i++) {
    const byte = displayBuffer[i];
    hex += ("0" + byte.toString(16)).slice(-2) + " ";
    ascii += byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".";
    if ((i + 1) % 16 === 0 || i === displayBuffer.length - 1) {
      output += `${offset.toString(16).padStart(8, "0")}  ${hex.padEnd(
        48,
        " "
      )}|${ascii}|\n`;
      hex = "";
      ascii = "";
      offset += 16;
    }
  }
  if (truncated) {
    output += `[Truncated ${buffer.length - maxLength} bytes]`;
  }
  return output;
}

export function bytearray_to_buffer(
  bytearray: number[],
  offset: number = 0,
  length: number = 0
) {
  if (length == 0) {
    length = bytearray.length;
  }
  const javaBytes: number[] = [];
  for (let i = offset; i < offset + length; i++) {
    javaBytes.push(bytearray[i] & 0xff);
  }
  const buffer = Buffer.from(javaBytes);
  return buffer;
}
