/*
Only functions for using katra with ethereum.
Only dependencies are katra and lib sodium and ethereum libs
*/

const _sodium = require('libsodium-wrappers');
const Wallet = require('ethereumjs-wallet');
const eth_utils = require('ethereumjs-util');
const Web3 = require('web3');
const ProviderEngine = require('web3-provider-engine');
const RpcSubprovider = require('web3-provider-engine/subproviders/rpc');
const WalletSubprovider = require('web3-provider-engine/subproviders/wallet');

const init_sodium = async () => {
  await _sodium.ready;
  return _sodium;
};

const get_wallet_from_keypair = async ({ keypair }) => {
  const sodium = await init_sodium();
  const curve25519_privateKey = sodium.crypto_sign_ed25519_sk_to_curve25519(
    sodium.from_hex(keypair.privateKey)
  );
  const wallet = Wallet.fromPrivateKey(
    new Buffer(sodium.to_hex(curve25519_privateKey), 'hex')
  );
  return wallet;
};

const get_web3_from_private_key = async ({ private_key, provider_url }) => {
  const sodium = await init_sodium();
  const curve25519_privateKey = sodium.crypto_sign_ed25519_sk_to_curve25519(
    sodium.from_hex(private_key)
  );
  const wallet = Wallet.fromPrivateKey(
    new Buffer(sodium.to_hex(curve25519_privateKey), 'hex')
  );
  const engine = new ProviderEngine();
  if (wallet) {
    engine.addProvider(new WalletSubprovider(wallet, {}));
  }
  engine.addProvider(
    new RpcSubprovider({
      rpcUrl: provider_url
    })
  );
  engine.start();
  return {
    web3: new Web3(engine),
    engine
  };
};

const get_web3 = ({ provider_url }) => {
  return {
    web3: new Web3(new Web3.providers.HttpProvider(provider_url))
  };
};

const ciphertext_id_to_address = async ({ ciphertext_id }) => {
  const sodium = await init_sodium();
  const curve25519_public_key = sodium.to_hex(
    sodium.crypto_sign_ed25519_pk_to_curve25519(
      sodium.from_hex(ciphertext_id.primary.publicKey)
    )
  );
  const pubKey = Buffer.from(curve25519_public_key);
  const address = eth_utils.pubToAddress(pubKey);
  return '0x' + address.toString('hex');
};

const send_wei = async (web3, from_address, to_address, amount_wei) => {
  return new Promise((resolve, reject) => {
    web3.eth.sendTransaction(
      {
        from: from_address,
        to: to_address,
        value: amount_wei
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

module.exports = {
  ciphertext_id_to_address,
  get_wallet_from_keypair,
  get_web3_from_private_key,
  get_web3,
  send_wei
};
