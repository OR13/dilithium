const { getSodium } = require('../../lib');

module.exports = {
  'asymmetric-create-keypair': async () => {
    const sodium = await getSodium();
    let keypair = sodium.crypto_box_keypair();
    return {
      publicKey: sodium.to_hex(keypair.publicKey),
      privateKey: sodium.to_hex(keypair.privateKey)
    };
  },
  'asymmetric-encrypt': async args => {
    const { payload, privateKey, publicKey } = args;
    const sodium = await getSodium();
    const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
    const ciphertext = sodium.crypto_box_easy(
      payload,
      nonce,
      sodium.from_hex(publicKey),
      sodium.from_hex(privateKey)
    );
    return {
      nonce: sodium.to_hex(nonce),
      ciphertext: sodium.to_hex(ciphertext)
    };
  },
  'asymmetric-decrypt': async args => {
    const { payload, publicKey, privateKey } = args;
    const sodium = await getSodium();
    const decrypted = sodium.crypto_box_open_easy(
      sodium.from_hex(payload.ciphertext),
      sodium.from_hex(payload.nonce),
      sodium.from_hex(publicKey),
      sodium.from_hex(privateKey)
    );
    return new Buffer(decrypted).toString();
  },
  'asymmetric-sign': async function(args) {
    const sodium = await getSodium();
    const signature = sodium.crypto_sign(
      args.message,
      sodium.from_hex(args.privateKey)
    );
    return sodium.to_hex(signature);
  },
  'asymmetric-verify': async function(args) {
    const sodium = await getSodium();
    let data = sodium.crypto_sign_open(
      sodium.from_hex(args.message),
      sodium.from_hex(args.publicKey)
    );
    return new Buffer(data).toString();
  }
};
