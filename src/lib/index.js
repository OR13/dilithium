const _sodium = require('libsodium-wrappers');

const _ = require('lodash');
const Web3 = require('web3');

const bip39 = require('bip39');
const Wallet = require('ethereumjs-wallet');
const hdkey = require('ethereumjs-wallet/hdkey');
const ProviderEngine = require('web3-provider-engine');
const RpcSubprovider = require('web3-provider-engine/subproviders/rpc');
const WalletSubprovider = require('web3-provider-engine/subproviders/wallet');

const path = require('path');
const fetch = require('node-fetch');
const fs = require('fs');
const fse = require('fs-extra');

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

const sendWei = async (web3, fromAddress, toAddress, amountWei) => {
  return new Promise((resolve, reject) => {
    web3.eth.sendTransaction(
      {
        from: fromAddress,
        to: toAddress,
        value: amountWei
      },
      (err, txhash) => {
        if (err) {
          reject(err);
        }
        resolve(txhash);
      }
    );
  });
};

const getWeb3 = async (providerUrl, wallet) => {
  const engine = new ProviderEngine();
  if (wallet) {
    engine.addProvider(new WalletSubprovider(wallet, {}));
  }
  engine.addProvider(
    new RpcSubprovider({
      rpcUrl: providerUrl
    })
  );
  engine.start();
  return new Web3(engine);
};

const keypair_to_hex = (sodium, keypair) => {
  return {
    publicKey: sodium.to_hex(keypair.publicKey),
    privateKey: sodium.to_hex(keypair.privateKey)
  };
};

const keypair_from_hex = (sodium, keypair) => {
  return {
    publicKey: sodium.from_hex(keypair.publicKey),
    privateKey: sodium.from_hex(keypair.privateKey)
  };
};

const ed25519_keypair_to_curve25519_keypair = (sodium, ed25519_keypair) => {
  let curve25519_keypair = {
    publicKey: sodium.crypto_sign_ed25519_pk_to_curve25519(
      ed25519_keypair.publicKey
    ),
    privateKey: sodium.crypto_sign_ed25519_sk_to_curve25519(
      ed25519_keypair.privateKey
    )
  };
  return curve25519_keypair;
};

const getWalletFromPrivateKey = sodium => {
  const keypair = sodium.crypto_sign_keypair();
  const curve25519_privateKey = sodium.crypto_sign_ed25519_sk_to_curve25519(
    keypair.privateKey
  );
  const wallet = Wallet.fromPrivateKey(
    new Buffer(sodium.to_hex(curve25519_privateKey), 'hex')
  );
  return wallet;
};

const getWalletFromMnemonic = sodium => {
  const mnemonic = bip39.generateMnemonic();
  const hdwallet = hdkey.fromMasterSeed(bip39.mnemonicToSeed(mnemonic));
  // Get the first account using the standard hd path.
  const walletHDPath = "m/44'/60'/0'/0/";
  const wallet = hdwallet.derivePath(walletHDPath + '0').getWallet();
  return wallet;
};

const getKeyFromShareDir = async shareDir => {
  let fileNamesInSharesDir = fs.readdirSync(shareDir);
  let sharesJson = await Promise.all(
    fileNamesInSharesDir.map(async filename => {
      let buf = await readFile(path.join(shareDir, filename));
      return JSON.parse(buf.toString());
    })
  );
  let shares = _.map(sharesJson, share => {
    return share.share;
  });
  return shares;
};

module.exports = {
  getSodium,
  getKeyFromShareDir,
  generateSecretKey,
  writeFile,
  readFile,
  getDecryptedAccount,
  getEncryptedAccount,
  getWalletFromPrivateKey,
  getWalletFromMnemonic,
  getWeb3,
  sendWei,
  saveObject,
  loadObject,
  keypair_to_hex,
  keypair_from_hex,
  ed25519_keypair_to_curve25519_keypair,
  getKeyFromPassword
};
