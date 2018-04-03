const Wallet = require('ethereumjs-wallet');
const asymmetricLib = require('../asymmetric/asymmetricLib');
const symmetricLib = require('../symmetric/symmetricLib');
const thresholdLib = require('../threshold/thresholdLib');

const {
  getSodium,
  keypair_to_hex,
  keypair_from_hex,
  ed25519_keypair_to_curve25519_keypair,
  getKeyFromShareDir
} = require('../../lib');

const getProofOfPrimaryBackupControl = async (
  sodium,
  primaryPublicKey,
  backupPrivate
) => {
  const signature = await asymmetricLib['asymmetric-sign']({
    message: primaryPublicKey,
    privateKey: backupPrivate
  });
  return sodium.to_hex(signature);
};

const getTransmuteId = async (
  sodium,
  name,
  primary_key,
  primary_keypair,
  recovery_keypair,
  previousTransmuteId
) => {
  const recovery_claim = await getProofOfPrimaryBackupControl(
    sodium,
    primary_keypair.publicKey,
    recovery_keypair.privateKey
  );
  const plainTextID = {
    name: name,
    primary_key,
    primary_keypair,
    recovery_keypair,
    recovery_claim
  };

  // generate a symmetric recovery_key used to encrypt the recovery_keypair
  const recovery_key = sodium.to_hex(
    sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES)
  );

  // use recovery_key to encrypt recovery_keypair
  const recovery_keypair_encrypted = await symmetricLib['symmetric-encrypt']({
    data: JSON.stringify(recovery_keypair),
    key: recovery_key
  });

  // shatter the symmetric recovery_key into shares
  const { shares, hash } = await thresholdLib['threshold-shatter-key']({
    key: recovery_key,
    share_num: 3,
    share_threshold: 2
  });

  // encrypt the primary_keypair with the primary_key (derived from user password + salt)
  const primary_keypair_encrypted = await symmetricLib['symmetric-encrypt']({
    data: JSON.stringify(primary_keypair),
    key: primary_key.key
  });

  const primary_curve25519_keypair = keypair_to_hex(
    sodium,
    ed25519_keypair_to_curve25519_keypair(
      sodium,
      keypair_from_hex(sodium, primary_keypair)
    )
  );
  const wallet = Wallet.fromPrivateKey(
    new Buffer(primary_curve25519_keypair.privateKey, 'hex')
  );

  const primary_address = '0x' + wallet.getAddress().toString('hex');

  const cipherTextID = {
    name: plainTextID.name,
    primary_address,
    primary_key_salt: primary_key.salt,
    primary_ed25519_public_key: primary_keypair.publicKey,
    primary_curve25519_public_key: primary_curve25519_keypair.publicKey,
    primary_keypair_encrypted,
    recovery_keypair_encrypted,
    recovery_key: {
      sha256_of_key: hash,
      share_num: 3,
      share_threshold: 2
    },
    recovery_claim,
    recovery_claims_history: []
  };

  if (previousTransmuteId) {
    cipherTextID.recovery_claims_history = [
      previousTransmuteId.recovery_claim,
      ...previousTransmuteId.recovery_claims_history
    ];
  }
  return {
    identity: cipherTextID,
    shares
  };
};

module.exports = {
  'identity-create': async args => {
    const sodium = await getSodium();
    const primary_key = await symmetricLib['symmetric-create-key'](args);
    const primary_keypair = keypair_to_hex(
      sodium,
      sodium.crypto_sign_keypair()
    );
    const recovery_keypair = keypair_to_hex(
      sodium,
      sodium.crypto_sign_keypair()
    );

    return await getTransmuteId(
      sodium,
      args.name,
      primary_key,
      primary_keypair,
      primary_keypair
    );
  },
  'identity-recover': async args => {
    const sodium = await getSodium();
    const transmuteId = require('../../../transmute-id.json');
    let shares = await getKeyFromShareDir(args.sharesDir);
    let key = await thresholdLib['threshold-recover-key'](shares);
    if (key.length !== 64) {
      throw new Error('Not enough shares to recover key.');
    }
    let decrypted_recovery_keypair = JSON.parse(
      await symmetricLib['symmetric-decrypt']({
        key: key,
        data: transmuteId.recovery_keypair_encrypted.encrypted,
        nonce: transmuteId.recovery_keypair_encrypted.nonce
      })
    );
    let verifiedSig = await asymmetricLib['asymmetric-verify']({
      message: sodium.from_hex(transmuteId.recovery_claim),
      publicKey: decrypted_recovery_keypair.publicKey
    });
    if (verifiedSig === transmuteId.primary_ed25519_public_key) {
      console.log('recovery_claim validated.');
    } else {
      throw new Error(
        'recovery_claim validation failed. primary_ed25519_public_key was not signed with the recovered private key.'
      );
    }
    const primary_keypair = decrypted_recovery_keypair;
    const recovery_keypair = keypair_to_hex(
      sodium,
      sodium.crypto_sign_keypair()
    );
    const recovered_primary_key = await symmetricLib['symmetric-recover-key']({
      salt: transmuteId.primary_key_salt,
      password: args.password
    });
    const primary_key = {
      key: recovered_primary_key,
      salt: transmuteId.primary_key_salt
    };
    let new_id = await getTransmuteId(
      sodium,
      transmuteId.name,
      primary_key,
      primary_keypair,
      recovery_keypair,
      transmuteId
    );
    return new_id;
  }
};
