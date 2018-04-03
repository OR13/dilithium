const asymmetricLib = require('./asymmetricLib');

// > console.log(Buffer.from("Hello World").toString('base64'));
// SGVsbG8gV29ybGQ=
// > console.log(Buffer.from("SGVsbG8gV29ybGQ=", 'base64').toString('ascii'))
// Hello World

module.exports = vorpal => {
  vorpal
    .command(
      'asymmetric-create-key',
      'generate a new public/private key pair with libsodium.'
    )
    .action(async (args, callback) => {
      let keypair = await asymmetricLib['asymmetric-create-keypair']();
      vorpal.logger.info('created: ' + JSON.stringify(keypair, null, 2) + '\n');
      callback();
    });

  vorpal
    .command(
      'asymmetric-encrypt <senderPrivateKey> <recipientPublicKey> <message>',
      'authenticated encryption with libsodium'
    )
    .action(async (args, callback) => {
      let result = await asymmetricLib['asymmetric-encrypt']({
        payload: args.message,
        senderPrivateKey: args.senderPrivateKey,
        recipientPublicKey: args.recipientPublicKey
      });
      let b64EncodedResult = Buffer.from(
        JSON.stringify(result, null, 2)
      ).toString('base64');
      vorpal.logger.info('encrypted: ' + b64EncodedResult + '\n');
      callback();
    });

  vorpal
    .command(
      'asymmetric-decrypt <senderPublicKey> <recipientPrivateKey> <message>',
      'authenticated decryption with libsodium'
    )
    .action(async (args, callback) => {
      let data = Buffer.from(args.message, 'base64').toString('ascii');
      let message = JSON.parse(data);
      let result = await asymmetricLib['asymmetric-decrypt']({
        payload: message,
        senderPublicKey: args.senderPublicKey,
        recipientPrivateKey: args.recipientPrivateKey
      });
      vorpal.logger.info('decrypted: ' + result + '\n');
      callback();
    });

  return vorpal;
};
