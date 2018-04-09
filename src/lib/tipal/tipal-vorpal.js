const path = require('path');
const fs = require('fs');
const fse = require('fs-extra');
const _ = require('lodash');

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

const katra = require('../katra');
const tipal = require('./tipal');

module.exports = vorpal => {
  vorpal
    .command('default-accounts', 'show the default accounts')
    .action(async (args, callback) => {
      const provider_url = 'http://localhost:8545';
      const { web3 } = await tipal.get_web3({
        provider_url
      });
      let accounts = await web3.eth.getAccounts();
      vorpal.logger.log(
        JSON.stringify(
          {
            accounts
          },
          null,
          2
        )
      );
      callback();
    });

  vorpal
    .command('balance <target_file>', 'show the balance of a given wallet')
    .action(async (args, callback) => {
      const ciphertext_id = JSON.parse(
        (await readFile(args.target_file)).toString()
      );
      const { web3 } = await tipal.get_web3({
        provider_url: 'http://localhost:8545'
      });
      let balance = await web3.eth.getBalance(ciphertext_id.ethereum_address);
      vorpal.logger.log(
        JSON.stringify(
          {
            address: ciphertext_id.ethereum_address,
            balance
          },
          null,
          2
        )
      );
      callback();
    });

  vorpal
    .command(
      'fund-from-default <target_file> [amount_wei]',
      'fund a target file from default accounts'
    )
    .types({ string: ['_'] })
    .action(async (args, callback) => {
      const FUND_AMOUNT_WEI = args.options.amount_wei || 420000050000000;
      const ciphertext_id = JSON.parse(
        (await readFile(args.target_file)).toString()
      );
      const { web3 } = await tipal.get_web3({
        provider_url: 'http://localhost:8545'
      });
      const accounts = await web3.eth.getAccounts();
      const txhash = await tipal.send_wei(
        web3,
        accounts[0],
        ciphertext_id.ethereum_address,
        FUND_AMOUNT_WEI
      );
      let balance = await web3.eth.getBalance(ciphertext_id.ethereum_address);
      vorpal.logger.log(
        JSON.stringify(
          {
            address: ciphertext_id.ethereum_address,
            balance,
            txhash
          },
          null,
          2
        )
      );
      callback();
    });

  vorpal
    .command(
      'send-wei <password> <target_file> <to_address> <amount_wei>',
      'fund transmute-id. password required.'
    )
    .types({ string: ['_'] })
    .action(async (args, callback) => {
      const ciphertext_id = JSON.parse(
        (await readFile(args.target_file)).toString()
      );

      // console.log(ciphertext_id)
      let key = await katra.key_from_password_and_salt({
        password: args.password,
        salt: ciphertext_id.id_password_salt
      });
      // console.log(key)
      let privateKey = await katra.decrypt_json({
        data: ciphertext_id.primary.privateKey,
        key
      });
      // console.log(privateKey);
      const { web3 } = await tipal.get_web3_from_private_key({
        private_key: privateKey,
        provider_url: 'http://localhost:8545'
      });

      const accounts = await web3.eth.getAccounts();
      // console.log(accounts);
      let balance = await web3.eth.getBalance(ciphertext_id.ethereum_address);

      // console.log(args.amount_wei)

      let txhash = await tipal.send_wei(
        web3,
        accounts[0],
        args.to_address,
        args.amount_wei
      );

      vorpal.logger.log(
        JSON.stringify(
          {
            address: accounts[0],
            balance,
            txhash
          },
          null,
          2
        )
      );
      callback();
    });

  return vorpal;
};
