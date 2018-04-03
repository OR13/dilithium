const Wallet = require('ethereumjs-wallet');
const asymmetricLib = require('../asymmetric/asymmetricLib');
const symmetricLib = require('../symmetric/symmetricLib');
const thresholdLib = require('../threshold/thresholdLib');

const {
  getSodium,
  keypair_to_hex,
  keypair_from_hex,
  ed25519_keypair_to_curve25519_keypair
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

  // console.log(proofOfBackupControl);
  // let verifiedSig = await asymmetricLib['asymmetric-verify']({
  //   message: result,
  //   publicKey: recovery_keypair.ed25519_keypair.publicKey
  // });
  // console.log('verifiedSig: ', verifiedSig);
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
    const recovery_claim = await getProofOfPrimaryBackupControl(
      sodium,
      primary_keypair.publicKey,
      recovery_keypair.privateKey
    );
    const plainTextID = {
      name: args.name,
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
        // do not leak key here...
        // key: backupEncryptionKey,
        // shares
      },
      recovery_claim
    };

    // console.log('cipherTextID', JSON.stringify(cipherTextID, null, 2));

    return {
      identity: cipherTextID,
      shares
    };
  }
};

// const encryptID = identity => {
//   return {
//     name: identity.name,
//     address: identity.address,
//     primary_keypair: {}
//   };
// };

// asymmetric: {
//   meta: {
//     encryption: {
//       'Key exchange': 'X25519',
//       Encryption: 'XSalsa20 stream cipher',
//       Authentication: 'Poly1305 MAC'
//     },
//     signature: {
//       Algorithm: 'Ed25519'
//     }
//     meta: {
//       Encryption: 'XSalsa20 stream cipher',
//       Authentication: 'Poly1305 MAC'
//     },
//   },

// const wallet = Wallet.fromPrivateKey(
//   new Buffer(primary_keypair.curve25519_keypair.privateKey, 'hex')
// );
// const address = wallet.getAddress().toString('hex');

// symmetricKeyData,
// identityKeypair,
// identityBackupKeypair

// console.log()
// console.log(pair.privateKey)
// const { message, privateKey } = args;
// let data = sodium.crypto_sign(message, pair.privateKey);
// // console.log(new Buffer(data).toString())
// let data2 = sodium.crypto_sign_open( data, pair.publicKey)
// console.log(new Buffer(data2).toString())

// let
// let identityKeypair = await asymmetricLib['asymmetric-create-keypair']();
// let identityBackupKeypair = await asymmetricLib[
//   'asymmetric-create-keypair'
// ]();

//  // console.log(args)
//  let pair = sodium.crypto_sign_keypair();
//  // console.log(pair.privateKey)
//  // const { message, privateKey } = args;

//  let pk = sodium.crypto_sign_ed25519_pk_to_curve25519(pair.publicKey);
//  let sk = sodium.crypto_sign_ed25519_sk_to_curve25519(pair.privateKey);

//  // console.log(convertedKey)
//  let keypair = sodium.crypto_box_keypair();

//  let data = await this['asymmetric-encrypt']({
//    payload: 'hello',
//    senderPrivateKey: sodium.to_hex(sk),
//    recipientPublicKey: sodium.to_hex(keypair.publicKey)
//  });

//  console.log(data);

//  let data2 = await this['asymmetric-decrypt']({
//    payload: data,
//    senderPublicKey: sodium.to_hex(pk),
//    recipientPrivateKey: sodium.to_hex(keypair.privateKey)
//  });

//  console.log('decrypted: ', data2)
