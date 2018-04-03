const Wallet = require('ethereumjs-wallet');
const asymmetricLib = require('../asymmetric/asymmetricLib');
const symmetricLib = require('../symmetric/symmetricLib');

const {
  getSodium,
  keypair_to_hex,
  get_new_ed25519_and_curve25519_keypairs
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
  //   publicKey: backup.ed25519_keypair.publicKey
  // });
  // console.log('verifiedSig: ', verifiedSig);
};

const encryptID = identity => {
  return {
    name: identity.name,
    address: identity.address,
    primary: {}
  };
};

module.exports = {
  'identity-create': async args => {
    const sodium = await getSodium();
    const primary = get_new_ed25519_and_curve25519_keypairs(sodium);
    const backup = get_new_ed25519_and_curve25519_keypairs(sodium);
    const symmetric = await symmetricLib['symmetric-create-key'](args);
    const wallet = Wallet.fromPrivateKey(
      new Buffer(primary.curve25519_keypair.privateKey, 'hex')
    );
    const address = wallet.getAddress().toString('hex');
    const proofOfBackupControl = await getProofOfPrimaryBackupControl(
      sodium,
      primary.ed25519_keypair.publicKey,
      backup.ed25519_keypair.privateKey
    );

    // TODO: make this object compatible with jose/jwks
    return {
      name: args.name,
      address,
      asymmetric: {
        meta: {
          encryption: {
            'Key exchange': 'X25519',
            Encryption: 'XSalsa20 stream cipher',
            Authentication: 'Poly1305 MAC'
          },
          signature: {
            Algorithm: 'Ed25519'
          }
        },
        primary,
        backup
      },
      symmetric: {
        meta: {
          Encryption: 'XSalsa20 stream cipher',
          Authentication: 'Poly1305 MAC'
        },
        key: symmetric.key,
        salt: symmetric.salt
      },
      proofOfBackupControl
    };
  }
};

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
