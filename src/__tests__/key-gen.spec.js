const _sodium = require('libsodium-wrappers');
const bip39 = require('bip39');
const hdkey = require('ethereumjs-wallet/hdkey');
const Wallet = require('ethereumjs-wallet');
const utils = require('ethereumjs-util');
let sodium;

const { getWeb3 } = require('../lib');

describe('key-gen', () => {
  beforeAll(async () => {
    await _sodium.ready;
    sodium = _sodium;
  });
  beforeEach(async () => {});

  it.skip('libsodium-wrappers crypto_sign', async () => {
    const alice = sodium.crypto_sign_keypair();
    const sig = sodium.crypto_sign('hello', alice.privateKey);
    const data = sodium.crypto_sign_open(sig, alice.publicKey);
    expect(new Buffer(data).toString()).toBe('hello');
  });

  it.skip('libsodium-wrappers crypto_box_easy', async () => {
    let alice = sodium.crypto_box_keypair();
    let bob = sodium.crypto_box_keypair();
    const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
    const ciphertext = sodium.crypto_box_easy(
      'hello',
      nonce,
      alice.publicKey,
      bob.privateKey
    );
    const decrypted = sodium.crypto_box_open_easy(
      ciphertext,
      nonce,
      bob.publicKey,
      alice.privateKey
    );
    let decoded = new Buffer(decrypted).toString();
    expect(decoded).toBe('hello');
  });
});

it('crypto_sign_keypair to ethereumjs-wallet ', async () => {
  let alice = sodium.crypto_sign_keypair();

  const curve25519_privateKey = sodium.crypto_sign_ed25519_sk_to_curve25519(
    alice.privateKey
  );
  const wallet = Wallet.fromPrivateKey(
    new Buffer(sodium.to_hex(curve25519_privateKey), 'hex')
  );
  const msg = 'hello';
  const msg_hash = utils.sha3(msg);

  // ECDSA
  const { v, r, s } = utils.ecsign(msg_hash, wallet._privKey);
  const pubKey = utils.ecrecover(msg_hash, v, r, s);
  const addr = utils.pubToAddress(pubKey);
  const wallet_address = '0x' + wallet.getAddress().toString('hex');
  expect('0x' + addr.toString('hex')).toBe(wallet_address);

  // console.log(sodium.to_hex(bob.publicKey))
  // console.log(pubKey.toString('hex'))
});

it.skip('BIP39 ECDSA ethereumjs-wallet libsodium-wrappers integration', async () => {
  const mnemonic = bip39.generateMnemonic();
  const hdwallet = hdkey.fromMasterSeed(bip39.mnemonicToSeed(mnemonic));
  const walletHDPath = "m/44'/60'/0'/0/";
  const wallet = hdwallet.derivePath(walletHDPath + '0').getWallet();

  const msg = 'hello';
  const msg_hash = utils.sha3(msg);

  // ECDSA
  const { v, r, s } = utils.ecsign(msg_hash, wallet._privKey);
  const pubKey = utils.ecrecover(msg_hash, v, r, s);
  const addr = utils.pubToAddress(pubKey);
  const wallet_address = '0x' + wallet.getAddress().toString('hex');
  expect('0x' + addr.toString('hex')).toBe(wallet_address);

  // console.log(sodium.to_hex(bob.publicKey))
  // console.log(pubKey.toString('hex'))
});

// DEAD BELOW
// console.log(decoded)

// console.log(rec.toString('hex'))
// console.log(msg_hash.toString('hex'))

// let web3 = await getWeb3('http://localhost:8545', wallet);
// let accounts = await web3.eth.getAccounts();

// let signature = await web3.eth.sign(msg, accounts[0]);
// let sig2 = await utils.fromRpcSig(signature)

// console.log(sig2);

// let rec = recover(msg, sig2)

// console.log(rec)

// HD WALLET SUPPORTS ENCRYPTION OUT OF THE BOX
//

// let data = sodium.crypto_sign('hello', sodium.from_hex(privateKey));
