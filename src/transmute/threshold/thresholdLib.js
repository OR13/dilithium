const secrets = require('secrets.js-grempe');
const crypto = require('crypto');
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

module.exports = {
  'threshold-shatter-key': async args => {
    const { key, share_num, share_threshold } = args;
    const sodium = await getSodium();
    var shares = secrets.share(key, share_num, share_threshold);
    const hash = crypto
      .createHash('sha256')
      .update(key)
      .digest('hex');
    return {
      shares,
      hash
    };
  },
  'threshold-recover-key': async shares => {
    return secrets.combine(shares);
  }
};
