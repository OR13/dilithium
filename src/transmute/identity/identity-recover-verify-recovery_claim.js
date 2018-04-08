const symmetricLib = require('../symmetric/symmetricLib');
const asymmetricLib = require('../asymmetric/asymmetricLib');

module.exports = async args => {
  const { recovery_claim, recovery_keypair, primary_ed25519_public_key } = args;
  // console.log('recovery_keypair: ', recovery_keypair);

  let verifiedSig = await asymmetricLib['asymmetric-verify']({
    message: recovery_claim,
    publicKey: recovery_keypair.publicKey
  });

  // console.log('verifiedSig: ', verifiedSig)

  return verifiedSig === primary_ed25519_public_key;
};
