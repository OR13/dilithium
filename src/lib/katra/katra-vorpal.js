const path = require('path');
const fs = require('fs');
const fse = require('fs-extra');
const _ = require('lodash');
const _sodium = require('libsodium-wrappers');

const init_sodium = async () => {
  await _sodium.ready;
  return _sodium;
};

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

const getSharesFromDir = async shareDir => {
  let fileNamesInSharesDir = fs.readdirSync(shareDir);
  let sharesJson = await Promise.all(
    fileNamesInSharesDir.map(async filename => {
      let buf = await readFile(path.join(shareDir, filename));
      return JSON.parse(buf.toString());
    })
  );
  let shares = _.map(sharesJson, share => {
    return share.share;
  });
  return shares;
};

const saveShares = async (ciphertext_id, shares, shares_dir) => {
  await Promise.all(
    shares.map((share, i) => {
      let shareId = 'share.' + i + '.json';
      let sharePath = path.join(shares_dir, shareId);
      let shareJson = JSON.stringify(
        {
          id: i,
          // sha256_of_key: identity.recovery_key.sha256_of_key,
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
};

const katra = require('./katra');

module.exports = vorpal => {
  vorpal
    .command(
      'katra create <password>',
      'create a katra.json file in the current directory.'
    )
    .action(async (args, callback) => {
      const primary = await katra.new_keypair();
      const recovery = await katra.new_keypair();
      const plaintext_id = await katra.generate_id({
        primary,
        recovery
      });
      const {
        ciphertext_id,
        shares
      } = await katra.plaintext_to_ciphertext_and_shares({
        plaintext_id,
        password: args.password
      });
      await saveShares(ciphertext_id, shares, './recovery-shares');
      await writeFile('./katra.json', JSON.stringify(ciphertext_id, null, 2));
      console.log(
        JSON.stringify({
          integrity: await katra.get_ciphertext_id_integrity({ ciphertext_id })
        })
      );
      callback();
    });

  vorpal
    .command(
      'katra verify <target_file> <integrity>',
      'compare a target file ciphertext_id to an integrity hash.'
    )
    .action(async (args, callback) => {
      let data = (await readFile(args.target_file)).toString();
      // console.log(data);
      let integrity_of_target = await katra.get_ciphertext_id_integrity({
        ciphertext_id: JSON.parse(data)
      });
      // console.log(integrity_of_target);
      if (integrity_of_target !== args.integrity) {
        throw new Error('Integrity check failed.');
      }
      console.log(
        JSON.stringify({
          integrity: true
        })
      );
      callback();
    });

  vorpal
    .command(
      'katra recover <old_password> <new_password> <target_file> <shares_dir> [integrity]',
      'recover a target file '
    )
    .action(async (args, callback) => {
      let compromised_ciphertext_id = JSON.parse(
        (await readFile(args.target_file)).toString()
      );

      if (args.options.integrity) {
        let current_integrity = await katra.get_ciphertext_id_integrity({
          ciphertext_id: compromised_ciphertext_id
        });

        if (current_integrity !== args.options.integrity) {
          throw new Error('Integrity check failed.');
        }
      }

      let shares = await getSharesFromDir(args.shares_dir);
      const compromised_id = await katra.ciphertext_and_shares_to_plaintext({
        password: args.old_password,
        ciphertext_id: compromised_ciphertext_id,
        shares
      });

      const recovered_id = await katra.recover_id({
        compromised_id
      });

      const safe = await katra.plaintext_to_ciphertext_and_shares({
        plaintext_id: recovered_id,
        password: args.new_password
      });
      await saveShares(safe.ciphertext_id, safe.shares, './recovery-shares');
      await writeFile(
        './katra.json',
        JSON.stringify(safe.ciphertext_id, null, 2)
      );
      console.log(
        JSON.stringify({
          integrity: await katra.get_ciphertext_id_integrity({
            ciphertext_id: safe.ciphertext_id
          })
        })
      );
      // console.log(plaintext_id, shares);
      callback();
    });

  vorpal
    .command(
      'change-password <old_password> <new_password> <target_file>',
      'change the password for a transmute_id'
    )
    .action(async (args, callback) => {
      const sodium = await init_sodium();
      let ciphertext_id = JSON.parse(
        (await readFile(args.target_file)).toString()
      );
      
      let key = await katra.key_from_password_and_salt({
        password: args.old_password,
        salt: ciphertext_id.id_password_salt
      });
      // console.log(key)
      let privateKey = await katra.decrypt_json({
        data: ciphertext_id.primary.privateKey,
        key
      });

      const id_password_salt = sodium.to_hex(sodium.randombytes_buf(
        sodium.crypto_pwhash_SALTBYTES
      ));
      // console.log(id_password_salt)
    
      const id_password_key = await katra.key_from_password_and_salt({
        password: args.new_password,
        salt: id_password_salt
      });

      ciphertext_id.primary.privateKey = await katra.encrypt_json({
        data: privateKey,
        key: id_password_key
      }),

      ciphertext_id.id_password_salt = id_password_salt

      // console.log(ciphertext_id)

      await writeFile('./katra.json', JSON.stringify(ciphertext_id, null, 2));
      console.log(
        JSON.stringify({
          integrity: await katra.get_ciphertext_id_integrity({ ciphertext_id })
        })
      );
  
      callback();
    });

  // vorpal
  //   .command('trace-claims', 'show the default accounts')
  //   .action(async (args, callback) => {
  //     await require('./identity-trace-claims')(args);
  //     callback();
  //   });

  return vorpal;
};
