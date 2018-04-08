const katra = require('../katra');

describe('katra.trace_id', () => {
  it('returns the chain of public keys referenced in an id', async () => {
    const primary = await katra.new_keypair();
    const recovery = await katra.new_keypair();
    let current_id = await katra.generate_id({
      primary,
      recovery
    });
    let count = 0;
    while (count < 3) {
      current_id = await katra.recover_id({
        compromised_id: current_id
      });
      count++;
    }
    const trace = katra.trace_id(current_id);
    // console.log(trace);
  });
});
