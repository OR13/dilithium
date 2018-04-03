const path = require('path');
const fs = require('fs');

const {
  getWeb3,
  writeFile,
  getEncryptedAccount,
  getDecryptedAccount
} = require('../lib');

module.exports = vorpal => {
  vorpal
    .command('create-account <password>', 'create an encrypted web3 account.')
    .option('-F, --force', 'OVERWRITES YOUR ACCOUNT.')
    .action(async (args, callback) => {
      const writeAccountToDisk = async () => {
        const web3 = getWeb3();
        let data = web3.eth.accounts.create(web3.utils.randomHex(32));
        let account = web3.eth.accounts.create(web3.utils.randomHex(32));
        let encryptedAccount = account.encrypt(args.password);
        await writeFile(
          './encryptedAccount.json',
          JSON.stringify(encryptedAccount, null, 2)
        );
        console.log('./encryptedAccount.json written to disk.');
      };

      if (fs.existsSync('./encryptedAccount.json') && !args.options.force) {
        vorpal.logger.warn('Account already exists.');
        vorpal.logger.log(
          '\nTo reset use: tranmsute create-web3-account <new-password> -F\n'
        );
      } else {
        await writeAccountToDisk();
      }

      callback();
    });

  vorpal
    .command(
      'address',
      'show the address and balance of ./encryptedAccount.json'
    )
    .action(async (args, callback) => {
      if (!fs.existsSync('./encryptedAccount.json')) {
        vorpal.logger.error('No account found.');
        vorpal.logger.info(
          'To create an account use: create-web3-account <password> '
        );
      } else {
        let web3 = getWeb3();
        let encryptedAccount = await getEncryptedAccount();
        vorpal.logger.log('Your address is: \n\n0x' + encryptedAccount.address);
        let balance = await web3.eth.getBalance(
          '0x' + encryptedAccount.address
        );
        vorpal.logger.log('\nYour balance is: ' + balance + '\n');
      }
      callback();
    });

  vorpal
    .command(
      'fund <address> <amountWei>',
      'fund an address from the default account.'
    )
    .types({ string: ['_'] })
    .action(async (args, callback) => {
      const web3 = getWeb3();
      const relic = new T.Relic(web3);
      const accounts = await relic.getAccounts();
      const tx = await relic.sendWei(accounts[0], args.address, args.amountWei);
      vorpal.logger.info(tx);
      let balance = await web3.eth.getBalance(args.address);
      vorpal.logger.log('\nAddress: ' + args.address);
      vorpal.logger.log('\nBalance: ' + balance + '\n');
      callback();
    });

  return vorpal;
};
