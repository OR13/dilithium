const symmetricLib = require('../symmetric/symmetricLib');
const thresholdLib = require('../threshold/thresholdLib');

const { getKeyFromShareDir } = require('../../lib');

module.exports = async args => {
  const { recovery_keypair_encrypted, sharesDir } = args;
  let shares = await getKeyFromShareDir(sharesDir);
  let recovery_key = await thresholdLib['threshold-recover-key'](shares);
  if (recovery_key.length !== 64) {
    throw new Error('Not enough shares to recover key.');
  }
  let recovery_keypair = JSON.parse(
    await symmetricLib['symmetric-decrypt']({
      key: recovery_key,
      data: recovery_keypair_encrypted.encrypted,
      nonce: recovery_keypair_encrypted.nonce
    })
  );

  return recovery_keypair;
};
