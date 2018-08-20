const bip39 = require('bip39');
const hdkey = require('hdkey');
const ethUtil = require('ethereumjs-util')

const mnemonic = bip39.generateMnemonic(); //generates string

console.log(mnemonic)

const seed = bip39.mnemonicToSeed(mnemonic); //creates seed buffer

const root = hdkey.fromMasterSeed(seed);
const masterPrivateKey = root.privateKey.toString('hex');

console.log(root)

// Note: Treat your root.publicKey as securely as you would treat your masterPrivateKey as you can still generate the addresses without it.

const addrNode = root.derive("m/44'/60'/0'/0/0"); //line 1

const pubKey = ethUtil.privateToPublic(addrNode._privateKey);
const addr = ethUtil.publicToAddress(pubKey).toString('hex');
const address = ethUtil.toChecksumAddress(addr);

console.log(address)