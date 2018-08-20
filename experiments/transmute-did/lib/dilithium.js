// this module contains all functions used for identity management.
// it can only be 1 file.

const _sodium = require('libsodium-wrappers');
const secrets = require('secrets.js-grempe');
const openpgp = require('openpgp');
const bip39 = require('bip39');
const hdkey = require('hdkey');
const ethUtil = require('ethereumjs-util');

const { keccak256 } = require('js-sha3');

const init_sodium = async () => {
  await _sodium.ready;
  return _sodium;
};

const generate_bip39_mneumonic = () => {
  return bip39.generateMnemonic(); //generates string
};

const new_keypair = async () => {
  const sodium = await init_sodium();
  let keypair = sodium.crypto_sign_keypair();
  return {
    publicKey: sodium.to_hex(keypair.publicKey),
    privateKey: sodium.to_hex(keypair.privateKey),
    keyType: keypair.keyType
  };
};

const identity_continuity_claim = async ({ primary, recovery }) => {
  const sodium = await init_sodium();
  const message = `${primary.publicKey} <- ${recovery.publicKey}`;

  const primary_attestation = sodium.crypto_sign_detached(
    message,
    sodium.from_hex(primary.privateKey)
  );

  const recovery_attestation = sodium.crypto_sign_detached(
    message,
    sodium.from_hex(recovery.privateKey)
  );

  return {
    message,
    primary_attestation: sodium.to_hex(primary_attestation),
    recovery_attestation: sodium.to_hex(recovery_attestation)
  };
};

const message_to_primary_recovery = message => {
  return {
    primary: {
      publicKey: message.split('<-')[0].trim()
    },
    recovery: {
      publicKey: message.split('<-')[1].trim()
    }
  };
};

// returns true if all identities in the chain
// have signatures supporting their links.
const verify_history = async ({ primary, history }) => {
  const sodium = await init_sodium();
  let index = 0;

  // make sure the current public key is attached to history
  let last_public_key_in_history = history[0].message.split('<-')[0].trim();
  if (primary.publicKey !== last_public_key_in_history) {
    throw new Error('primary.publicKey is not last_public_key_in_history');
  }

  while (index < history.length - 1) {
    // console.log('checking ', index, ' to ', index + 1);
    let current_claim = history[index];
    let previous_claim = history[index + 1];
    let current = message_to_primary_recovery(current_claim.message);
    let previous = message_to_primary_recovery(previous_claim.message);
    if (current.primary.publicKey !== previous.recovery.publicKey) {
      throw new Error(
        'expected: current.primary.publicKey !== previous.recovery.publicKey'
      );
    }
    const previous_claim_was_signed_by_primary = sodium.crypto_sign_verify_detached(
      sodium.from_hex(previous_claim.primary_attestation),
      previous_claim.message,
      sodium.from_hex(previous.primary.publicKey)
    );
    const previous_claim_was_signed_by_recovery = sodium.crypto_sign_verify_detached(
      sodium.from_hex(previous_claim.recovery_attestation),
      previous_claim.message,
      sodium.from_hex(previous.recovery.publicKey)
    );
    const previous_claim_was_signed_by_primary_and_recovery =
      previous_claim_was_signed_by_primary &&
      previous_claim_was_signed_by_recovery;
    if (!previous_claim_was_signed_by_primary_and_recovery) {
      throw new Error(
        'expected: previous_claim_was_signed_by_primary_and_recovery'
      );
    }
    index++;
  }

  return true;
};

const recover_id = async ({ compromised_id }) => {
  const sodium = await init_sodium();
  const verified = true;
  if (verified) {
    let primary = compromised_id.recovery;
    let recovery = await new_keypair();
    return generate_id({
      primary,
      recovery,
      history: [
        await identity_continuity_claim({ primary, recovery }),
        ...compromised_id.history
      ]
    });
  }
};

const trace_id = transmute_id => {
  let res = '';
  res += `${transmute_id.primary.publicKey} <- ${
    transmute_id.recovery.publicKey
  }`;
  res += '\n';
  res += transmute_id.history
    .map(claim => {
      return claim.message;
    })
    .join('\n');
  return res;
};

const encrypt_json = async ({ data, key }) => {
  const sodium = await init_sodium();
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  const data_string = JSON.stringify(data);
  const encrypted = sodium.crypto_secretbox_easy(
    data_string,
    nonce,
    sodium.from_hex(key)
  );
  return {
    nonce: sodium.to_hex(nonce),
    encrypted: sodium.to_hex(encrypted)
  };
};

const decrypt_json = async ({ data, key }) => {
  const sodium = await init_sodium();
  // console.log(data, key);
  const decrypted = sodium.crypto_secretbox_open_easy(
    sodium.from_hex(data.encrypted),
    sodium.from_hex(data.nonce),
    sodium.from_hex(key)
  );
  return JSON.parse(new Buffer(decrypted).toString());
};

const plaintext_to_ciphertext_and_shares = async ({
  plaintext_id,
  password
}) => {
  const sodium = await init_sodium();
  const id_password_salt = sodium.to_hex(
    sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES)
  );
  // console.log(id_password_salt)

  const id_password_key = await key_from_password_and_salt({
    password,
    salt: id_password_salt
  });

  // console.log(id_password_key);

  // console.log(id_password_key);
  // generate a symmetric recovery_key used to encrypt the recovery_keypair
  const recovery_key = sodium.to_hex(
    sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES)
  );
  const share_num = 3;
  const share_threshold = 2;

  const shares = secrets.share(recovery_key, share_num, share_threshold);

  return {
    ciphertext_id: {
      ethereum_address: plaintext_id.ethereum_address,
      id_password_salt: id_password_salt,
      primary: {
        publicKey: plaintext_id.primary.publicKey,
        privateKey: await encrypt_json({
          data: plaintext_id.primary.privateKey,
          key: id_password_key
        }),
        keyType: plaintext_id.primary.keyType
      },
      recovery: {
        publicKey: plaintext_id.recovery.publicKey,
        privateKey: await encrypt_json({
          data: plaintext_id.recovery.privateKey,
          key: recovery_key
        }),
        keyType: plaintext_id.recovery.keyType
      },
      history: plaintext_id.history
    },
    shares
  };
};

const key_from_password_and_salt = async ({ password, salt }) => {
  const sodium = await init_sodium();
  const id_password_key = sodium.to_hex(
    sodium.crypto_pwhash(
      sodium.crypto_box_SEEDBYTES,
      password,
      sodium.from_hex(salt),
      sodium.crypto_pwhash_OPSLIMIT_MIN,
      sodium.crypto_pwhash_MEMLIMIT_MIN,
      sodium.crypto_pwhash_ALG_DEFAULT
    )
  );
  return id_password_key;
};
const ciphertext_and_shares_to_plaintext = async ({
  password,
  ciphertext_id,
  shares
}) => {
  const sodium = await init_sodium();

  // console.log(ciphertext_id);

  const id_password_key = await key_from_password_and_salt({
    password,
    salt: ciphertext_id.id_password_salt
  });

  // console.log(id_password_key)
  const recovery_key = secrets.combine(shares);
  return {
    ethereum_address: ciphertext_id.ethereum_address,
    primary: {
      publicKey: ciphertext_id.primary.publicKey,
      privateKey: await decrypt_json({
        data: ciphertext_id.primary.privateKey,
        key: id_password_key
      }),
      keyType: ciphertext_id.primary.keyType
    },
    recovery: {
      publicKey: ciphertext_id.recovery.publicKey,
      privateKey: await decrypt_json({
        data: ciphertext_id.recovery.privateKey,
        key: recovery_key
      }),
      keyType: ciphertext_id.recovery.keyType
    },
    history: ciphertext_id.history
  };
};

const get_ciphertext_id_integrity = async ({ ciphertext_id }) => {
  const sodium = await init_sodium();
  const ciphertext_id_string = JSON.stringify(ciphertext_id);
  return sodium.to_hex(
    sodium.crypto_generichash(
      sodium.crypto_generichash_BYTES_MIN,
      ciphertext_id_string
    )
  );
};

const test_ciphertext_id_integrity = async ({ ciphertext_id, integrity }) => {
  return integrity === (await get_ciphertext_id_integrity({ ciphertext_id }));
};

const generate_salt = async () => {
  const sodium = await init_sodium();
  return sodium.to_hex(sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES));
};

const generate_openpgp_armored_keypair = async ({ name, passphrase }) => {
  const secOptions = {
    userIds: [
      {
        name: name
      }
    ],
    curve: 'secp256k1',
    passphrase: passphrase
  };

  // create primary key
  const primaryKeyPair = await openpgp.generateKey(secOptions);
  return {
    publicKey: primaryKeyPair.publicKeyArmored,
    privateKey: primaryKeyPair.privateKeyArmored
  };
};

// a json document with plaintext private keys and symmetric keys...
// an intermediate representation, never to be stored or written to disk....
const generate_plaintext_master_transmute_did_keystore_document = ({
  MASTER_MNEUMONIC,
  MASTER_SALT,
  MASTER_SYMMETRIC_KEY,
  MASTER_PGP_KEYPAIR,
  MASTER_SODIUM_KEYPAIR
}) => {
  return {
    MASTER_MNEUMONIC,
    MASTER_SALT,
    MASTER_SYMMETRIC_KEY,
    MASTER_PGP_KEYPAIR,
    MASTER_SODIUM_KEYPAIR
  };
};

const encrypt_master_transmute_did_keystore_document = async json_data => {
  //   add validation here...
  let {
    MASTER_MNEUMONIC,
    MASTER_SALT,
    MASTER_SYMMETRIC_KEY,
    MASTER_PGP_KEYPAIR,
    MASTER_SODIUM_KEYPAIR
  } = json_data;

  return {
    salt: MASTER_SALT,
    data: await encrypt_json({
      data: json_data,
      key: MASTER_SYMMETRIC_KEY
    })
  };
};

const decrypt_transmute_master_keystore_document = async ({
  passphrase,
  document
}) => {
  const MASTER_SYMMETRIC_KEY = await key_from_password_and_salt({
    password: passphrase,
    salt: document.salt
  });

  return decrypt_json({
    data: document.data,
    key: MASTER_SYMMETRIC_KEY
  });
};

const getDID = ({ publicKey }) => `did:tst:0x${keccak256(publicKey)}`;

const mneumonic_to_public_key = mnemonic => {
  const seed = bip39.mnemonicToSeed(mnemonic); //creates seed buffer

  const root = hdkey.fromMasterSeed(seed);
  const masterPrivateKey = root.privateKey.toString('hex');

  console.log(root);

  // Note: Treat your root.publicKey as securely as you would treat your masterPrivateKey as you can still generate the addresses without it.

  const addrNode = root.derive("m/44'/60'/0'/0/0"); //line 1

  const pubKey = ethUtil.privateToPublic(addrNode._privateKey);

  return pubKey;
};

const public_key_to_address = pubKey => {
  const addr = ethUtil.publicToAddress(pubKey).toString('hex');
  const address = ethUtil.toChecksumAddress(addr);
  return address;
};

const generate_public_transmute_did_document_from_plaintext_master = document => {
  // console.log('TOLO!!!', document)

  const did = getDID({
    publicKey: document.MASTER_SODIUM_KEYPAIR.publicKey
  });

  // console.log('did!!!', did)

  const ethPubKey = mneumonic_to_public_key(document.MASTER_MNEUMONIC);

  return {
    '@context': 'https://w3id.org/did/v1',
    id: did,
    publicKey: [
      {
        id: `${did}#keys-1`,
        type: 'Ed25519VerificationKey2018',
        owner: did,
        publicKey: document.MASTER_SODIUM_KEYPAIR.publicKey
      },
      {
        id: `${did}#keys-2`,
        type: 'Secp256k1VerificationKey2018',
        owner: did,
        publicKeyPem: document.MASTER_PGP_KEYPAIR.publicKey
      },
      {
        id: `${did}#keys-3`,
        type: 'Secp256k1VerificationKey2018',
        owner: did,
        publicKey: ethPubKey.toString('hex')
      }
    ],
    authentication: [
      {
        type: 'Ed25519SignatureAuthentication2018',
        publicKey: `${did}#keys-1`
      }
    ]
  };
};

module.exports = {
  generate_bip39_mneumonic,
  new_keypair,
  generate_salt,
  key_from_password_and_salt,
  encrypt_json,
  decrypt_json,
  identity_continuity_claim,
  recover_id,
  verify_history,
  trace_id,
  plaintext_to_ciphertext_and_shares,
  ciphertext_and_shares_to_plaintext,
  test_ciphertext_id_integrity,
  get_ciphertext_id_integrity,
  generate_openpgp_armored_keypair,
  generate_plaintext_master_transmute_did_keystore_document,
  encrypt_master_transmute_did_keystore_document,
  decrypt_transmute_master_keystore_document,
  generate_public_transmute_did_document_from_plaintext_master,
  public_key_to_address
};
