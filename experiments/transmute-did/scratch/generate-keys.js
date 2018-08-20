const path = require('path');

const openpgp = require('openpgp');

const web3 = require('web3');

const { writeFile } = require('./utils');

module.exports.generateKeys = async args => {
  const { name, passphrase } = args;
  const secOptions = {
    userIds: [
      {
        name: name
      }
    ],
    curve: 'secp256k1',
    passphrase: passphrase
  };

  // create primary key
  const primaryKeyPair = await openpgp.generateKey(secOptions);
  let primarySk = openpgp.key.readArmored(primaryKeyPair.privateKeyArmored)
    .keys[0];
  await primarySk.decrypt(passphrase);

  // create recovery key
  const recoveryKeyPair = await openpgp.generateKey(secOptions);
  const recoverySk = openpgp.key.readArmored(recoveryKeyPair.privateKeyArmored)
    .keys[0];
  await recoverySk.decrypt(passphrase);

  // sign primary key with recovery key
  primarySk = await primarySk.signPrimaryUser([recoverySk]);

  // lock private keys before exporting them
  await primarySk.encrypt(passphrase);
  await recoverySk.encrypt(passphrase);

  let transmuteDir = path.join(__dirname, 'data');

  // write private keys temporarily to secrets directory
  await writeFile(
    path.join(transmuteDir, 'primary_public.key'),
    primaryKeyPair.publicKeyArmored
  );
  await writeFile(
    path.join(transmuteDir, 'primary_private.key'),
    primarySk.armor()
  );

  await writeFile(
    path.join(transmuteDir, 'recovery_public.key'),
    recoveryKeyPair.publicKeyArmored
  );
  await writeFile(
    path.join(transmuteDir, 'recovery_private.key'),
    recoverySk.armor()
  );


  let ethAccount = web3.eth.accounts.create();

  console.log(ethAccount)

  console.info('\n Keys written to disk...\n');
};

module.exports.generateKeys({
  name: 'bob',
  passphrase: 'chillbob'
});
