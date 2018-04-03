const {
  getSodium,
  writeFile,
  readFile,
  loadObject,
  saveObject,
  getKeyFromPassword
} = require('../../lib');

module.exports = {
  'symmetric-create-key': async args => {
    const { password } = args;
    const sodium = await getSodium();
    const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
    const key = await getKeyFromPassword(sodium, password, salt);
    return {
      key: sodium.to_hex(key),
      salt: sodium.to_hex(salt)
    };
  },
  'symmetric-recover-key': async args => {
    const { salt, password } = args;
    const sodium = await getSodium();
    const key = await getKeyFromPassword(
      sodium,
      password,
      sodium.from_hex(salt)
    );
    return sodium.to_hex(key);
  },
  'symmetric-encrypt': async args => {
    const { data, key } = args;
    const sodium = await getSodium();
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const encrypted = sodium.crypto_secretbox_easy(
      data,
      nonce,
      sodium.from_hex(key)
    );
    return {
      nonce: sodium.to_hex(nonce),
      encrypted: sodium.to_hex(encrypted)
    };
  },
  'symmetric-decrypt': async args => {
    const { data, nonce, key } = args;
    const sodium = await getSodium();
    const decrypted = sodium.crypto_secretbox_open_easy(
      sodium.from_hex(data),
      sodium.from_hex(nonce),
      sodium.from_hex(key)
    );

    const decryptedPlainText = new Buffer(decrypted).toString();
    return decryptedPlainText;
  }
};
