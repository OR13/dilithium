const path = require('path');
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

const identityLib = require('./identityLib');
const asymmetricLib = require('../asymmetric/asymmetricLib');
const symmetricLib = require('../symmetric/symmetricLib');
const thresholdLib = require('../threshold/thresholdLib');

module.exports = vorpal => {
  vorpal
    .command('identity-create <name> <password>', 'create a transmute identity')
    .action(async (args, callback) => {
      const { name } = args;
      const target = '.';
      const { identity, shares } = await identityLib['identity-create'](args);
      // vorpal.logger.info(
      //   'identity: ' + JSON.stringify(identity, null, 2) + '\n'
      // );
      console.log('identity created.');
      await Promise.all(
        shares.map((share, i) => {
          let shareId = 'share.' + i + '.json';
          let sharePath = path.join(target, 'recovery-shares', shareId);
          let shareJson = JSON.stringify(
            {
              id: i,
              sha256_of_key: identity.recovery_key.sha256_of_key,
              num_shares: 3,
              share_threshold: 2,
              share: share
            },
            null,
            2
          );
          return writeFile(sharePath, shareJson);
        })
      );
      let identityPath = path.join(target, 'transmute-id.json');
      await writeFile(identityPath, JSON.stringify(identity, null, 2));
      callback();
    });

  vorpal
    .command(
      'identity-recover <password> <sharesDir>',
      'recover an execute an identity recover operation via shares'
    )
    .action(async (args, callback) => {
      const { name } = args;
      const target = '.';
      const { identity, shares } = await identityLib['identity-recover'](args);
      // vorpal.logger.info(
      //   'identity: ' + JSON.stringify(identity, null, 2) + '\n'
      // );
      await Promise.all(
        shares.map((share, i) => {
          let shareId = 'share.' + i + '.json';
          let sharePath = path.join(target, 'recovery-shares', shareId);
          let shareJson = JSON.stringify(
            {
              id: i,
              sha256_of_key: identity.recovery_key.sha256_of_key,
              num_shares: 3,
              share_threshold: 2,
              share: share
            },
            null,
            2
          );
          return writeFile(sharePath, shareJson);
        })
      );
      let identityPath = path.join(target, 'transmute-id.json');
      await writeFile(identityPath, JSON.stringify(identity, null, 2));
      callback();
    });

  vorpal
    .command('accounts', 'show the default accounts')
    .action(async (args, callback) => {
      const web3 = await getWeb3('http://localhost:8545');
      let accounts = await web3.eth.getAccounts();
      vorpal.logger.log('\nAccounts: ' + JSON.stringify(accounts, null, 2));
      callback();
    });

  vorpal
    .command('balance', 'show the balance and balance the default transmute-id')
    .action(async (args, callback) => {
      let transmuteId = require('../../../transmute-id.json');
      // console.log(transmuteId);
      const web3 = await getWeb3('http://localhost:8545');
      let balance = await web3.eth.getBalance(transmuteId.primary_address);
      vorpal.logger.log('\nAddress: ' + transmuteId.primary_address);
      vorpal.logger.log('\nBalance: ' + balance + '\n');

      callback();
    });

  vorpal
    .command(
      'fund-transmute-id',
      'fund transmute-id from default testrpc accounts.'
    )
    .types({ string: ['_'] })
    .action(async (args, callback) => {
      let transmuteId = require('../../../transmute-id.json');
      const web3 = await getWeb3('http://localhost:8545');
      const defaultAccounts = await web3.eth.getAccounts();
      const FUND_AMOUNT = '500000000000013';
      await sendWei(
        web3,
        defaultAccounts[0],
        transmuteId.primary_address,
        FUND_AMOUNT
      );
      let balance = await web3.eth.getBalance(transmuteId.primary_address);
      vorpal.logger.log('\nAddress: ' + transmuteId.primary_address);
      vorpal.logger.log('\nBalance: ' + balance + '\n');
      callback();
    });

  vorpal
    .command(
      'send-wei <password> <address> <amountWei> ',
      'fund transmute-id. password required.'
    )
    .types({ string: ['_'] })
    .action(async (args, callback) => {
      const sodium = await getSodium();
      let transmuteId = require('../../../transmute-id.json');
      let primaryEncryptionKey = await symmetricLib['symmetric-recover-key']({
        salt: transmuteId.primary_key_salt,
        password: args.password
      });
      let decryptedPrimaryKeyPair = JSON.parse(
        await symmetricLib['symmetric-decrypt']({
          key: primaryEncryptionKey,
          data: transmuteId.primary_keypair_encrypted.encrypted,
          nonce: transmuteId.primary_keypair_encrypted.nonce
        })
      );
      let decryptedCurve25519KeyPair = keypair_to_hex(
        sodium,
        ed25519_keypair_to_curve25519_keypair(
          sodium,
          keypair_from_hex(sodium, decryptedPrimaryKeyPair)
        )
      );
      const wallet = Wallet.fromPrivateKey(
        new Buffer(decryptedCurve25519KeyPair.privateKey, 'hex')
      );
      const web3 = await getWeb3('http://localhost:8545', wallet);
      let txhash = await sendWei(
        web3,
        transmuteId.primary_address,
        args.address,
        args.amountWei
      );
      vorpal.logger.log('\nTxHash: ' + txhash + '\n');
      callback();
    });

  return vorpal;
};
