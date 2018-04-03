const _sodium = require('libsodium-wrappers');

const path = require('path');
const fetch = require('node-fetch');
const fs = require('fs');
const fse = require('fs-extra');
const Web3 = require('web3');
const ethereumjsWallet = require('ethereumjs-wallet');
const ProviderEngine = require('web3-provider-engine');
const RpcSubprovider = require('web3-provider-engine/subproviders/rpc');
const WalletSubprovider = require('web3-provider-engine/subproviders/wallet');

const transmuteConfig = require('../../env.json');
const RPC_HOST = transmuteConfig.web3ProviderUrl;

var store = require('json-fs-store')('./store');

const getSodium = async () => {
  await _sodium.ready;
  const sodium = _sodium;
  return sodium;
};

const generateSecretKey = async () => {
  const sodium = await getSodium();
  return sodium.crypto_secretstream_xchacha20poly1305_keygen();
};
const saveObject = obj => {
  return new Promise((resolve, reject) => {
    store.add(obj, function(err) {
      if (err) throw err; // err if the save failed
      resolve(true);
    });
  });
};

const loadObject = objId => {
  return new Promise((resolve, reject) => {
    store.load(objId, function(err, object) {
      if (err) throw err; // err if the save failed
      resolve(object);
    });
  });
};

const getWeb3 = account => {
  try {
    const engine = new ProviderEngine();

    if (account) {
      var wallet = ethereumjsWallet.fromPrivateKey(
        new Buffer(account.privateKey.replace('0x', ''), 'hex')
      );
      engine.addProvider(new WalletSubprovider(wallet, {}));
    }

    engine.addProvider(
      new RpcSubprovider({
        rpcUrl: RPC_HOST
      })
    );
    engine.start();

    let web3 = new Web3(engine);
    return web3;
  } catch (e) {
    console.log('error: ', e);
  }
};

const getEncryptedAccount = async () => {
  return new Promise((resolve, reject) => {
    fse.readFile('./encryptedAccount.json', (err, data) => {
      if (err) {
        reject(err);
      }
      resolve(JSON.parse(data));
    });
  });
};

const getDecryptedAccount = async password => {
  const web3 = new Web3();
  const encryptedAccount = await getEncryptedAccount();
  return web3.eth.accounts.decrypt(encryptedAccount, password);
};

const writeFile = async (filePath, fileData) => {
  return new Promise((resolve, reject) => {
    fse.outputFile(filePath, fileData, err => {
      if (err) {
        reject(err);
      }
      resolve(true);
    });
  });
};

const readFile = async filePath => {
  return new Promise((resolve, reject) => {
    fse.readFile(filePath, (err, fileData) => {
      if (err) {
        reject(err);
      }
      resolve(fileData);
    });
  });
};

// return a argon2 password hash string... for verifying user passwords...
const getArgon2PwHashStr = (sodium, password) => {
  return new Promise((resolve, reject) => {
    var hashed_password = sodium.crypto_pwhash_str(
      password,
      sodium.crypto_pwhash_OPSLIMIT_MIN,
      sodium.crypto_pwhash_MEMLIMIT_MIN
    );
    return resolve(hashed_password);
  });
};

// return Uint8Array Key of size sodium.crypto_box_SEEDBYTES
const getKeyFromPassword = (sodium, password, salt) => {
  return new Promise((resolve, reject) => {
    var hashed_password = sodium.crypto_pwhash(
      sodium.crypto_box_SEEDBYTES,
      password,
      salt,
      sodium.crypto_pwhash_OPSLIMIT_MIN,
      sodium.crypto_pwhash_MEMLIMIT_MIN,
      sodium.crypto_pwhash_ALG_DEFAULT
    );
    return resolve(hashed_password);
  });
};



const keypair_to_hex = (sodium, keypair) => {
  return {
    publicKey: sodium.to_hex(keypair.publicKey),
    privateKey: sodium.to_hex(keypair.privateKey)
  };
};

const get_new_ed25519_and_curve25519_keypairs = sodium => {
  let ed25519_keypair = sodium.crypto_sign_keypair();
  let curve25519_keypair = {
    publicKey: sodium.crypto_sign_ed25519_pk_to_curve25519(
      ed25519_keypair.publicKey
    ),
    privateKey: sodium.crypto_sign_ed25519_sk_to_curve25519(
      ed25519_keypair.privateKey
    )
  };
  return {
    ed25519_keypair: keypair_to_hex(sodium, ed25519_keypair),
    curve25519_keypair: keypair_to_hex(sodium, curve25519_keypair)
  };
};

module.exports = {
  getSodium,
  generateSecretKey,
  writeFile,
  readFile,
  getDecryptedAccount,
  getEncryptedAccount,
  getWeb3,
  saveObject,
  loadObject,
  keypair_to_hex,
  get_new_ed25519_and_curve25519_keypairs,
  getKeyFromPassword
};
