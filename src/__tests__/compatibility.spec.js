const _sodium = require('libsodium-wrappers');
const openpgp = require('openpgp');
const Wallet = require('ethereumjs-wallet');
const utils = require('ethereumjs-util');

const Promise = require('bluebird');
const fs = Promise.promisifyAll(require('fs'));

let sodium;

describe('compatibility', () => {
  beforeAll(async () => {
    await _sodium.ready;
    sodium = _sodium;
  });

  beforeEach(async () => {});

  it('gpg -> openpgp', async () => {
    const alice_passphrase = 'secret';
    const bob_passphrase = 'secret2';
    const alice_public_key_armored = (await fs.readFileAsync(
      './data/public.key'
    )).toString();
    const alice_private_key_armored = (await fs.readFileAsync(
      './data/private.key'
    )).toString();
    const alice_private_key_obj = openpgp.key.readArmored(
      alice_private_key_armored
    ).keys[0];
    await alice_private_key_obj.decrypt(alice_passphrase);
    const bobKeyObject = await openpgp.generateKey({
      userIds: [{ name: 'Bob Smith', email: 'bob@example.com' }],
      curve: 'ed25519',
      passphrase: bob_passphrase
    });

    const bobPrivKeyObj = openpgp.key.readArmored(
      bobKeyObject.privateKeyArmored
    ).keys[0];
    await bobPrivKeyObj.decrypt(bob_passphrase);

    const ciphertext = await openpgp.encrypt({
      data: 'Hello, World!', // input as String (or Uint8Array)
      publicKeys: openpgp.key.readArmored(bobKeyObject.publicKeyArmored).keys, // for encryption
      privateKeys: [alice_private_key_obj] // for signing (optional)
    });
    expect(ciphertext.data);

    const plaintext = await openpgp.decrypt({
      message: openpgp.message.readArmored(ciphertext.data), // parse armored message
      publicKeys: openpgp.key.readArmored(alice_public_key_armored).keys, // for verification (optional)
      privateKeys: [bobPrivKeyObj] // for decryption
    });
    // console.log(plaintext);
    expect(plaintext.data);
  });

  it('openpgp encrypt / decrypt', async () => {
    // generate a new ed25519 pgp key for jon snow
    const passphrase = 'super long and hard to guess secret';
    let options = {
      userIds: [{ name: 'Jon Snow', email: 'jon@example.com' }],
      curve: 'ed25519',
      passphrase: passphrase
    };
    const keyObject = await openpgp.generateKey(options);
    const { publicKeyArmored, privateKeyArmored } = keyObject;
    const pubkey = publicKeyArmored.toString(); // '-----BEGIN PGP PUBLIC KEY BLOCK ... END PGP PUBLIC KEY BLOCK-----';
    const privkey = privateKeyArmored.toString(); //'-----BEGIN PGP PRIVATE KEY BLOCK ... END PGP PRIVATE KEY BLOCK-----'; //encrypted private key
    const privKeyObj = openpgp.key.readArmored(privkey).keys[0];
    await privKeyObj.decrypt(passphrase);
    options = {
      data: 'Hello, World!', // input as String (or Uint8Array)
      publicKeys: openpgp.key.readArmored(pubkey).keys, // for encryption
      privateKeys: [privKeyObj] // for signing (optional)
    };
    const ciphertext = await openpgp.encrypt(options);
    expect(ciphertext.data);
    options = {
      message: openpgp.message.readArmored(ciphertext.data), // parse armored message
      publicKeys: openpgp.key.readArmored(pubkey).keys, // for verification (optional)
      privateKeys: [privKeyObj] // for decryption
    };
    const plaintext = await openpgp.decrypt(options);
    // console.log(plaintext)
    expect(plaintext.data);
  });

  it('openpgp -> libsodium -> ethereumjs-wallet', async () => {
    const options = {
      userIds: [{ name: 'Jon Snow', email: 'jon@example.com' }],
      curve: 'ed25519',
      passphrase: 'super long and hard to guess secret'
    };
    // generate a new ed25519 pgp key for jon snow
    const jon_smith_pgp = await openpgp.generateKey(options);
    const publicKey = openpgp.key.readArmored(jon_smith_pgp.publicKeyArmored)
      .keys[0];
    const publicKeyHex = sodium
      .to_hex(publicKey.primaryKey.params[1].data)
      .substring(2);
    const privateKey = openpgp.key.readArmored(jon_smith_pgp.privateKeyArmored)
      .keys[0];
    const privateKeyIsDecrypted = await privateKey.decrypt(options.passphrase);
    const privateKeyHex =
      sodium.to_hex(privateKey.primaryKey.params[2].data) + publicKeyHex;

    // use the pgp key pair with lib sodium to sign a message
    const message = `my message`;
    const primary_attestation = sodium.crypto_sign_detached(
      message,
      sodium.from_hex(privateKeyHex)
    );
    const data = sodium.crypto_sign_verify_detached(
      primary_attestation,
      message,
      sodium.from_hex(publicKeyHex)
    );

    // convert the private key to curve25519 for use with ethereum js wallet
    const curve25519_privateKey = sodium.crypto_sign_ed25519_sk_to_curve25519(
      sodium.from_hex(privateKeyHex)
    );
    const wallet = Wallet.fromPrivateKey(
      new Buffer(sodium.to_hex(curve25519_privateKey), 'hex')
    );
    const msg = 'hello';
    const msg_hash = utils.sha3(msg);
    const { v, r, s } = utils.ecsign(msg_hash, wallet._privKey);
    const pubKey = utils.ecrecover(msg_hash, v, r, s);
    const addr = utils.pubToAddress(pubKey);
    const wallet_address = '0x' + wallet.getAddress().toString('hex');
    expect('0x' + addr.toString('hex')).toBe(wallet_address);
  });
});
