let dilt = require('./lib/dilithium');
const path = require('path');

const { writeFile } = require('./utils');

let transmuteDir = path.join(__dirname, 'data');

(async () => {
  //   let salt = await dilt.generate_salt();
  //   let password = 'correct horse battery staple';

  //   let master_symmetric_key = await dilt.key_from_password_and_salt({
  //     password,
  //     salt
  //   });

  //   console.log(master_symmetric_key);

  //   let encrypted_wallet = await dilt.encrypt_json({
  //     data: {
  //       yolo: 1
  //     },
  //     key: master_symmetric_key
  //   });

  //   console.log(encrypted_wallet)

  //   let decrypted_wallet = await dilt.decrypt_json({
  //     data: encrypted_wallet,
  //     key: master_symmetric_key
  //   });

  //   console.log(decrypted_wallet)

  console.log(
    `

THIS IS TEST VERSION, WE WILL ONLY USE 1 PASSPHRASE. NOT SECURE

NOT SAFE.

DO NOT USE.

Welcome, this program will create a Decentralized Identity 
and the associated cryptographic keys.

    `
  );

  console.log(
    `
First, you must save a master mneumonic. Please read the following carefully.

- If you store it in digital format, you MUST use encryption. 
- If you store it in paper format, you should replicate it physically.
- Anyone who knows this mneumonic can impersonate you, read messages intended for you, steal from you, etc...
- If you lose your mneumonic you will lose the ability to use this identity.
- Protect your mneumonic as if your life depends on it.
- Do not share your mneumonic with anyone ever.
- Never publish or store your mneumonic in a place where someone other than you can access it.
- Seriously, if you loose this, its game over.

This is the LAST TIME your mneumonic will be displayed, if you do not record it, you will LOOSE YOUR IDENTITY.

    `
  );

  const MASTER_MNEUMONIC = await dilt.generate_bip39_mneumonic();

  console.log(
    `
${MASTER_MNEUMONIC}
    `
  );

  console.log(
    `
You must also store a MASTER_SALT. 
It is used to derrive a symmetric key from your mneumonic. 
Salts can be public, but you should never share any information 
with anyone that you do not NEED to.
    `
  );

  const MASTER_SALT = await dilt.generate_salt();

  //   console.log(MASTER_SALT);

  const MASTER_SYMMETRIC_KEY = await dilt.key_from_password_and_salt({
    password: MASTER_MNEUMONIC,
    salt: MASTER_SALT
  });

  //   console.log(MASTER_SYMMETRIC_KEY);

  const MASTER_PGP_KEYPAIR = await dilt.generate_openpgp_armored_keypair({
    passphrase: MASTER_MNEUMONIC,
    name: MASTER_SALT // could store name and email here... but then key is toxic.
  });

  //   console.log(MASTER_PGP_KEYPAIR);

  const MASTER_SODIUM_KEYPAIR = await dilt.new_keypair();

  //   console.log(MASTER_SODIUM_KEYPAIR);

  const PLAINTEXT_MASTER_TRANSMUTE_KEYSTORE_DOCUMENT = dilt.generate_plaintext_master_transmute_did_keystore_document(
    {
      MASTER_MNEUMONIC,
      MASTER_SALT,
      MASTER_SYMMETRIC_KEY,
      MASTER_PGP_KEYPAIR,
      MASTER_SODIUM_KEYPAIR
    }
  );

  //   console.log(PLAINTEXT_MASTER_TRANSMUTE_KEYSTORE_DOCUMENT);

  const CIPHERTEXT_MASTER_TRANSMUTE_KEYSTORE_DOCUMENT = await dilt.encrypt_master_transmute_did_keystore_document(
    PLAINTEXT_MASTER_TRANSMUTE_KEYSTORE_DOCUMENT
  );

  // console.log('CIPHERTEXT_MASTER_TRANSMUTE_KEYSTORE_DOCUMENT: ', CIPHERTEXT_MASTER_TRANSMUTE_KEYSTORE_DOCUMENT);

  const RECOVERED_MASTER_TRANSMUTE_KEYSTORE_DOCUMENT = await dilt.decrypt_transmute_master_keystore_document(
    {
      passphrase: MASTER_MNEUMONIC,
      document: CIPHERTEXT_MASTER_TRANSMUTE_KEYSTORE_DOCUMENT
    }
  );

  // console.log('RECOVERED_MASTER_TRANSMUTE_KEYSTORE_DOCUMENT: ', RECOVERED_MASTER_TRANSMUTE_KEYSTORE_DOCUMENT)

  const DID_DOCUMENT = dilt.generate_public_transmute_did_document_from_plaintext_master(
    PLAINTEXT_MASTER_TRANSMUTE_KEYSTORE_DOCUMENT
  );

  console.log('DID_DOCUMENT: ', DID_DOCUMENT);

  await writeFile(
    path.join(transmuteDir, 'DID_KEYSTORE_PLAINTEXT_DOCUMENT.json'),
    JSON.stringify(PLAINTEXT_MASTER_TRANSMUTE_KEYSTORE_DOCUMENT, null, 2)
  );

  await writeFile(
    path.join(transmuteDir, 'DID_KEYSTORE_CIPHERTEXT_DOCUMENT.json'),
    JSON.stringify(CIPHERTEXT_MASTER_TRANSMUTE_KEYSTORE_DOCUMENT, null, 2)
  );

  await writeFile(
    path.join(transmuteDir, 'DID_DOCUMENT.json'),
    JSON.stringify(DID_DOCUMENT, null, 2)
  );
})();
