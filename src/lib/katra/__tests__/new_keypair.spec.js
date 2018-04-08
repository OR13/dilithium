const katra = require('../katra');

describe('new_keypair', () => {
  it(' generates hex encoded ed25519 public private key pair', async () => {
    const keypair = await katra.new_keypair();
    expect(keypair.keyType).toBe('ed25519');
  });
});
