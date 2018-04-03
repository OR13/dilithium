const vorpal = require('vorpal')();
const vorpalLog = require('vorpal-log');
const vorpalTour = require('vorpal-tour');

vorpal.use(vorpalLog);

vorpal
  .command('version', 'display version information')
  .action(async (args, callback) => {
    vorpal.logger.info('dilithium: ' + require('../package.json').version);
    callback();
  });

require('./transmute/identity')(vorpal);
require('./transmute/asymmetric')(vorpal);
require('./transmute/symmetric')(vorpal);
require('./transmute/threshold')(vorpal);

vorpal
  .parse(process.argv)
  .delimiter('🦄   $')
  .show();
