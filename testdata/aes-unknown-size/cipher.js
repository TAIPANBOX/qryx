// Same shape in node: the pattern anchors on `aes` inside the string literal
// and stops there, so the -128- that follows it is never read as a key size.
const crypto = require('crypto');

function encrypt(key, iv, plaintext) {
  const c = crypto.createCipheriv('aes-128-cbc', key, iv);
  return Buffer.concat([c.update(plaintext), c.final()]);
}

module.exports = { encrypt };
