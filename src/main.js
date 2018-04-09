const KeenTracking = require('keen-tracking');
const vorpal = require('vorpal')();
const vorpalLog = require('vorpal-log');
const vorpalTour = require('vorpal-tour');

vorpal.use(vorpalLog);

const { keenConfig } = require('./config');
vorpal.keenConfig = keenConfig;

const client = new KeenTracking(keenConfig);

vorpal.recordEvent = (stream, event) => {
  return new Promise((resolve, reject) => {
    if (vorpal.keenConfig.sendTelemetry) {
      client.recordEvent(stream, event, (err, data) => {
        if (err) {
          reject(err);
        }
        resolve(event);
      });
    } else {
      resolve(true);
    }
  });
};

vorpal
  .command('version', 'display version information')
  .action(async (args, callback) => {
    const version = require('../package.json').version;
    vorpal.logger.info('dilithium: ' + version);
    await vorpal.recordEvent('command', {
      version
    });
    callback();
  });

require('./lib/katra/katra-vorpal')(vorpal);
require('./lib/tipal/tipal-vorpal')(vorpal);

vorpal
  .parse(process.argv)
  .delimiter('🦄   $')
  // .show();
