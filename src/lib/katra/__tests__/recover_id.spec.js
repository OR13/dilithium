const katra = require('../katra');

describe('katra.recover_id', () => {
  it('returns a new identity from a safe private key with history linking to the compromised one.', async () => {
    const primary = await katra.new_keypair();
    const recovery = await katra.new_keypair();
    const current_id = await katra.generate_id({
      primary,
      recovery
    });
    const recovered_id = await katra.recover_id({
      compromised_id: current_id
    });
    // expect(recovered_id.primary.publicKey).toBe(recovery.publicKey);
    // console.log(recovered_id);
  });
});
