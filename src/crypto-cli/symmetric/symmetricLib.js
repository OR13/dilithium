const {
  getSodium,
  writeFile,
  readFile,
  loadObject,
  saveObject,
  encrypt,
  decrypt,
  getKeyFromPassword
} = require('../../lib');

module.exports = {
  'symmetric-create-key': async (name, password) => {
    const sodium = await getSodium();
    const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
    let key = await getKeyFromPassword(sodium, password, salt);
    return {
      name,
      key: sodium.to_hex(key),
      salt: sodium.to_hex(salt)
    };
  },
  'symmetric-recover-key': async (name, password) => {
    const sodium = await getSodium();
    let stored = await loadObject(name);
    let key = await getKeyFromPassword(
      sodium,
      password,
      sodium.from_hex(stored.salt)
    );
    return {
      name,
      key: sodium.to_hex(key),
      salt: stored.salt
    };
  },
  'symmetric-encrypt': async (data, key) => {
    const sodium = await getSodium();
    const { nonce, encrypted } = encrypt(sodium, data, sodium.from_hex(key));
    return {
      nonce: sodium.to_hex(nonce),
      encrypted: sodium.to_hex(encrypted)
    };
  },
  'symmetric-decrypt': async (data, nonce, key) => {
    const sodium = await getSodium();
    const decrypted = decrypt(
      sodium,
      sodium.from_hex(data),
      sodium.from_hex(nonce),
      sodium.from_hex(key)
    );
    let decryptedPlainText = new Buffer(decrypted).toString();
    return decryptedPlainText;
  }
};
