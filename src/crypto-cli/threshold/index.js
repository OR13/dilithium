const fs = require('fs');
const path = require('path');
const _ = require('lodash');

const { readFile, saveObject } = require('../../lib');

const thresholdLib = require('./thresholdLib');

const getKeyFromShareDir = async shareDir => {
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

module.exports = vorpal => {
  vorpal
    .command(
      'threshold-shatter-key <key> <share_num> <share_threshold>',
      'shatter a key with shamir secret sharing and sha256.'
    )
    .action(async (args, callback) => {
      const { shares, hash } = await thresholdLib['threshold-shatter-key'](
        args.key,
        args.share_num,
        args.share_threshold
      );
      await Promise.all(
        shares.map((share, i) => {
          return saveObject({
            id: hash + '.share.' + i,
            digest: hash,
            num_shares: args.share_num,
            share_threshold: args.share_threshold,
            share: share
          });
        })
      );
      vorpal.logger.info('shattered key digest: ' + hash + '\n');
      callback();
    });

  vorpal
    .command('threshold-recover-key <name> <keySharesDirectory>', '')
    .action(async (args, callback) => {
      let shares = await getKeyFromShareDir(args.keySharesDirectory);
      let comb = await thresholdLib['threshold-recover-key'](shares);
      if (comb.length !== 64) {
        vorpal.logger.error('Not enough shares to recover key.\n');
        callback();
      }
      vorpal.logger.info('recovered key: ' + comb + '\n');
      callback();
    });
};
