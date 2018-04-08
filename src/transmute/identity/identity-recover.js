const Wallet = require('ethereumjs-wallet');
const asymmetricLib = require('../asymmetric/asymmetricLib');
const symmetricLib = require('../symmetric/symmetricLib');
const thresholdLib = require('../threshold/thresholdLib');
const crypto = require('crypto');
const path = require('path');

const {
  getSodium,
  readFile,
  writeFile,
  keypair_to_hex,
  keypair_from_hex,
  ed25519_keypair_to_curve25519_keypair
} = require('../../lib');

module.exports = async args => {
  const sodium = await getSodium();
  let transmute_id = await readFile(
    path.resolve(__dirname, '../../../transmute-id.json')
  );

  const id_disk_integrity = crypto
    .createHash('sha384')
    .update(transmute_id)
    .digest('hex');

  let integrity_match = id_disk_integrity === args.integrity;

  transmute_id = JSON.parse(transmute_id.toString());

  // IGNORE INTEGRITY
  // if (!integrity_match) {
  //   throw new Error('Integrity check failed. id has been tampered with.');
  // } else {
  //   console.log('integrity is valid.');
  // }

  const primary_keypair = await require('./identity-recover-primary-keypair')({
    password: args.old_password,
    primary_key_salt: transmute_id.primary_key_salt,
    primary_keypair_encrypted: transmute_id.primary_keypair_encrypted
  });
  // console.log('primary_keypair: ', primary_keypair);
  const recovery_keypair = await require('./identity-recover-recovery-keypair')(
    {
      sharesDir: args.shares_dir,
      recovery_keypair_encrypted: transmute_id.recovery_keypair_encrypted
    }
  );
  const recovery_claim_verified = await require('./identity-recover-verify-recovery_claim')(
    {
      primary_ed25519_public_key: transmute_id.primary_ed25519_public_key,
      recovery_claim: transmute_id.recovery_claim,
      recovery_keypair: recovery_keypair
    }
  );
  // console.log(recovery_claim_verified);
  if (recovery_claim_verified) {
    //  no op
  } else {
    throw new Error(
      'recovery_claim validation failed. primary_ed25519_public_key was not signed with the recovered private key.'
    );
  }

  // now create a new identity from the recovery key
  //
  //
  //
  const primary_key = await symmetricLib['symmetric-create-key']({
    password: args.new_password
  });
  const new_primary_keypair = recovery_keypair;
  const new_recovery_keypair = keypair_to_hex(
    sodium,
    sodium.crypto_sign_keypair()
  );

  const recovery_claim = await asymmetricLib['asymmetric-sign']({
    message: new_primary_keypair.publicKey,
    privateKey: new_recovery_keypair.privateKey
  });

  console.log('recovery_claim: ', recovery_claim);

  // generate a symmetric recovery_key used to encrypt the recovery_keypair
  const recovery_key = sodium.to_hex(
    sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES)
  );

  // use recovery_key to encrypt recovery_keypair
  const recovery_keypair_encrypted = await symmetricLib['symmetric-encrypt']({
    data: JSON.stringify(new_recovery_keypair),
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
    data: JSON.stringify(new_primary_keypair),
    key: primary_key.key
  });

  const primary_curve25519_keypair = keypair_to_hex(
    sodium,
    ed25519_keypair_to_curve25519_keypair(
      sodium,
      keypair_from_hex(sodium, new_primary_keypair)
    )
  );
  const wallet = Wallet.fromPrivateKey(
    new Buffer(primary_curve25519_keypair.privateKey, 'hex')
  );

  const primary_address = '0x' + wallet.getAddress().toString('hex');

  // console.log('recovery claims to be added to the new id: ', )
  const cipherTextID = {
    name: transmute_id.name,
    primary_address,
    primary_key_salt: primary_key.salt,
    primary_ed25519_public_key: new_primary_keypair.publicKey,
    primary_curve25519_public_key: primary_curve25519_keypair.publicKey,
    primary_keypair_encrypted,
    recovery_keypair_encrypted,
    recovery_key: {
      sha256_of_key: hash,
      share_num: 3,
      share_threshold: 2
    },
    recovery_claim,
    recovery_claims_history: [
      transmute_id.recovery_claim,
      ...transmute_id.recovery_claims_history
    ]
  };

  return {
    identity: cipherTextID,
    shares
  };
};
