const symmetricLib = require('../symmetric/symmetricLib');
const asymmetricLib = require('../asymmetric/asymmetricLib');

module.exports = async args => {
  const { old_password, new_password, transmute_id } = args;
  const new_transmute_id = {
    ...transmute_id
  };

  //   console.log(transmute_id)

  const primary_keypair = await require('./identity-recover-primary-keypair')({
    password: old_password,
    primary_key_salt: transmute_id.primary_key_salt,
    primary_keypair_encrypted: transmute_id.primary_keypair_encrypted
  });

  // //   console.log('primary_keypair: ', primary_keypair);

  const new_primary_key = await symmetricLib['symmetric-create-key']({
    password: new_password
  });

  // //   console.log('new_primary_key: ', new_primary_key);

  const primary_keypair_encrypted = await symmetricLib['symmetric-encrypt']({
    data: JSON.stringify(primary_keypair),
    key: new_primary_key.key
  });

  new_transmute_id.primary_key_salt = new_primary_key.salt;
  new_transmute_id.primary_keypair_encrypted = primary_keypair_encrypted;

  return new_transmute_id;
};
