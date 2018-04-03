const {
  getSodium,
  writeFile,
  readFile,
  loadObject,
  saveObject,
  encrypt,
  decrypt,
  getKeyFromPassword
} = require('../../lib');

const symmetricLib = require('./symmetricLib');

module.exports = vorpal => {
  vorpal
    .command(
      'symmetric-create-key <name> <password>',
      'use libsodium crypto_pwhash to derive a symmetric key from a password + salt.'
    )
    .action(async (args, callback) => {
      let { name, salt } = await symmetricLib['symmetric-create-key'](args);
      await saveObject({
        id: name,
        salt
      });
      vorpal.logger.info('created: ' + name + '\n');
      callback();
    });

  vorpal
    .command(
      'symmetric-recover-key <name> <password>',
      'use libsodium crypto_pwhash to recover a symmetric key from a password + salt.'
    )
    .action(async (args, callback) => {
      let { name, salt, key } = await symmetricLib['symmetric-recover-key'](
        args
      );
      vorpal.logger.info('recovered: ' + key + '\n');
      callback();
    });

  vorpal
    .command(
      'symmetric-encrypt <target> <key>',
      'encrypt a target file with key'
    )
    .action(async (args, callback) => {
      const sodium = await getSodium();
      let plainText = await readFile(args.target);
      let { nonce, encrypted } = await symmetricLib['symmetric-encrypt'](
        plainText,
        args.key
      );
      await writeFile(
        args.target + '.encrypted.json',
        JSON.stringify(
          {
            nonce,
            encrypted
          },
          null,
          2
        )
      );
      vorpal.logger.info('encrypted: ' + args.target + '.encrypted.json\n');
      callback();
    });

  vorpal
    .command(
      'symmetric-decrypt <target> <key>',
      'decrypt a target file with a key'
    )
    .action(async (args, callback) => {
      const sodium = await getSodium();
      let targetFile = await readFile(args.target);
      let targetJSON = JSON.parse(targetFile.toString());
      let decryptedPlainText = await symmetricLib['symmetric-decrypt'](
        targetJSON.encrypted,
        targetJSON.nonce,
        args.key
      );
      await writeFile(args.target + '.decrypted.txt', decryptedPlainText);
      vorpal.logger.info('decrypted: ' + args.target + '.encrypted.json\n');
      callback();
    });

  return vorpal;
};
