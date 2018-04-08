const path = require('path');
const { getSodium, readFile } = require('../../lib');

module.exports = async args => {
  const sodium = await getSodium();
  let transmute_id_file_buffer = await readFile(
    path.resolve(__dirname, '../../../transmute-id.json')
  );

  let transmute_id = JSON.parse(transmute_id_file_buffer.toString());
  console.log(transmute_id.recovery_claims_history);
};
