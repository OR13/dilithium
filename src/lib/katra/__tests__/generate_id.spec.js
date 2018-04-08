const katra = require('../katra');

describe('katra.generate_id', () => {
  it('generates a new id (primary, recovery keypairs)', async () => {
    const primary = await katra.new_keypair();
    const recovery = await katra.new_keypair();
    const current_id = await katra.generate_id({
      primary,
      recovery
    });
    // are keypairs stored correctly
    expect(current_id.primary.publicKey).toBe(primary.publicKey);
    expect(current_id.recovery.publicKey).toBe(recovery.publicKey);
    expect(current_id.history.length).toBe(1);
    // console.log(JSON.stringify(current_id, null, 2));
  });
});
