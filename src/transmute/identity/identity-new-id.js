const Wallet = require('ethereumjs-wallet');

const {
  getSodium,
  readFile,
  writeFile,
  getWeb3,
  sendWei,
  keypair_to_hex,
  keypair_from_hex,
  ed25519_keypair_to_curve25519_keypair
} = require('../../lib');

const asymmetricLib = require('../asymmetric/asymmetricLib');
const symmetricLib = require('../symmetric/symmetricLib');
const thresholdLib = require('../threshold/thresholdLib');

module.exports = async args => {
  const sodium = await getSodium();
  const { name, password } = args;
  const primary_key = await symmetricLib['symmetric-create-key']({
    password
  });

  const primary_keypair = keypair_to_hex(sodium, sodium.crypto_sign_keypair());
  const recovery_keypair = keypair_to_hex(sodium, sodium.crypto_sign_keypair());

  const recovery_claim = await asymmetricLib['asymmetric-sign']({
    message: primary_keypair.publicKey,
    privateKey: recovery_keypair.privateKey
  });

  console.log('recovery_claim: ', recovery_claim)
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

  return {
    identity: cipherTextID,
    shares
  };
};

// if (previousTransmuteId) {
//   cipherTextID.recovery_claims_history = [
//     previousTransmuteId.recovery_claim,
//     ...previousTransmuteId.recovery_claims_history
//   ];
// }
// const primary_keypair = decrypted_recovery_keypair;
// const recovery_keypair = keypair_to_hex(sodium, sodium.crypto_sign_keypair());

// let new_id = await getTransmuteId(
//   sodium,
//   transmuteId.name,
//   primary_key,
//   primary_keypair,
//   recovery_keypair,
//   transmuteId
// );
// return new_id;
