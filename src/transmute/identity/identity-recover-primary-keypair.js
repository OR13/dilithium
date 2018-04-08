const symmetricLib = require('../symmetric/symmetricLib');

module.exports = async args => {
  const { password, primary_key_salt, primary_keypair_encrypted } = args;
  const recovered_primary_key = await symmetricLib['symmetric-recover-key']({
    salt: primary_key_salt,
    password: args.password
  });
  const primary_key = {
    key: recovered_primary_key,
    salt: primary_key_salt
  };

  let decryptedPrimaryKeyPair;
  try {
    decryptedPrimaryKeyPair = JSON.parse(
      await symmetricLib['symmetric-decrypt']({
        key: recovered_primary_key,
        data: primary_keypair_encrypted.encrypted,
        nonce: primary_keypair_encrypted.nonce
      })
    );
  } catch (e) {
    if (e.message === 'wrong secret key for the given ciphertext') {
      throw new Error('Password is not correct.');
    }
  }

  return decryptedPrimaryKeyPair;
};
