const fs = require('fs-extra');
const openpgp = require('openpgp');

const lib = require('./lib');

module.exports.generateDID = async args => {
  console.log(args);
};

const openpgp_encryptMessage = async (message, privkey, passphrase, pubkey) => {
  const privKeyObj = openpgp.key.readArmored(privkey).keys[0];
  await privKeyObj.decrypt(passphrase);

  const options = {
    data: message, // input as String (or Uint8Array)
    publicKeys: openpgp.key.readArmored(pubkey).keys, // for encryption
    privateKeys: [privKeyObj] // for signing (optional)
  };

  return openpgp.encrypt(options).then(ciphertext => {
    let encrypted = ciphertext.data; // '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'
    return encrypted;
  });
};

const openpgp_decryptMessage = async (
  encrypted,
  privkey,
  passphrase,
  pubkey
) => {
  const privKeyObj = openpgp.key.readArmored(privkey).keys[0];
  await privKeyObj.decrypt(passphrase);

  const options = {
    message: openpgp.message.readArmored(encrypted), // parse armored message
    publicKeys: openpgp.key.readArmored(pubkey).keys, // for verification (optional)
    privateKeys: [privKeyObj] // for decryption
  };

  return openpgp.decrypt(options).then(plaintext => {
    // console.log(plaintext.data);
    return plaintext.data; // 'Hello, World!'
  });
};

(async () => {
  const primary_public_key_armored = fs
    .readFileSync('./data/primary_public.key')
    .toString();

  const primary_private_key_armored = fs
    .readFileSync('./data/primary_private.key')
    .toString();

  // console.log(primary_sk);

  const privKeyObj = (await openpgp.key.readArmored(
    primary_private_key_armored
  )).keys[0];

  const passphrase = 'chillbob';

  let encrypted_msg = await openpgp_encryptMessage(
    'hello world',
    primary_private_key_armored,
    passphrase,
    primary_public_key_armored
  );

  let recovered_data = await openpgp_decryptMessage(
    encrypted_msg,
    primary_private_key_armored,
    passphrase,
    primary_public_key_armored
  );

  console.log(encrypted_msg);
  console.log(recovered_data);
  
})();
