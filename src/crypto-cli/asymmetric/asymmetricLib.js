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
    const { payload, senderPrivateKey, recipientPublicKey } = args;
    const sodium = await getSodium();
    const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
    const ciphertext = sodium.crypto_box_easy(
      payload,
      nonce,
      sodium.from_hex(recipientPublicKey),
      sodium.from_hex(senderPrivateKey)
    );
    return {
      nonce: sodium.to_hex(nonce),
      ciphertext: sodium.to_hex(ciphertext)
    };
  },
  'asymmetric-decrypt': async args => {
    const { payload, senderPublicKey, recipientPrivateKey } = args;
    const sodium = await getSodium();
    const decrypted = sodium.crypto_box_open_easy(
      sodium.from_hex(payload.ciphertext),
      sodium.from_hex(payload.nonce),
      sodium.from_hex(senderPublicKey),
      sodium.from_hex(recipientPrivateKey)
    );
    return new Buffer(decrypted).toString();
  },
  'asymmetric-sign': async function(args) {
    const sodium = await getSodium();
    let data = sodium.crypto_sign(
      args.message,
      sodium.from_hex(args.privateKey)
    );
    // console.log(data);
    // console.log(new Buffer(data).toString())
    // let data2 = sodium.crypto_sign_open(data, pair.publicKey);
    // console.log(new Buffer(data2).toString());
    return data;
  },
  'asymmetric-verify': async function(args) {
    const sodium = await getSodium();
    let data = sodium.crypto_sign_open(
      args.message,
      sodium.from_hex(args.publicKey)
    );
    return new Buffer(data).toString();
  }
};
