


export const app_name = '放开那三国（送貂蝉）';


export const get_hexdump_from_arraybuffer = (data: ArrayBuffer) => {
  // Convert ArrayBuffer to hex dump
  const bytes = new Uint8Array(data);
  let hexDump = '';
  let asciiDump = '';

  for (let i = 0; i < bytes.length; i++) {
    // Add offset at start of each line
    if (i % 16 === 0) {
      if (i > 0) {
        hexDump += `  ${asciiDump}\n`;
        asciiDump = '';
      }
      hexDump += `${i.toString(16).padStart(8, '0')}: `;
    }

    // Add hex value
    hexDump += `${bytes[i].toString(16).padStart(2, '0')} `;

    // Add ASCII character if printable, otherwise add dot
    asciiDump += bytes[i] >= 32 && bytes[i] <= 126 ?
      String.fromCharCode(bytes[i]) : '.';
  }

  // Add padding and final ASCII section for last line
  const remaining = bytes.length % 16;
  if (remaining > 0) {
    hexDump += '   '.repeat(16 - remaining);
    hexDump += `  ${asciiDump}`;
  }
  return hexDump;
}