const sharp = require("sharp");
const fs = require("fs");
const path = require("path");
const source = path.join(__dirname, "..", "favicon.svg");
const out = path.join(__dirname, "..");
if (!fs.existsSync(source)) throw new Error("favicon.svg not found");
(async () => {
  for (const size of [32, 64, 180, 192, 512]) {
    await sharp(source).resize(size, size).png().toFile(path.join(out, size === 180 ? "apple-touch-icon.png" : `icon-${size}.png`));
  }
  // Produce a classic ICO file with a PNG-encoded 32px image entry.
  const png = await sharp(source).resize(32, 32).png().toBuffer();
  const header = Buffer.alloc(6); header.writeUInt16LE(0, 0); header.writeUInt16LE(1, 2); header.writeUInt16LE(1, 4);
  const entry = Buffer.alloc(16); entry[0]=32; entry[1]=32; entry[2]=0; entry[3]=0; entry.writeUInt16LE(1,4); entry.writeUInt16LE(32,6); entry.writeUInt32LE(png.length,8); entry.writeUInt32LE(22,12);
  fs.writeFileSync(path.join(out,"favicon.ico"), Buffer.concat([header,entry,png]));
  console.log("Generated PNG icons and favicon.ico");
})().catch(e=>{console.error(e);process.exit(1);});
