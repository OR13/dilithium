const _sodium = require('libsodium-wrappers');
let sodium;

const katra = require('../katra');

describe('katra.identity_continuity_claim', () => {
  beforeAll(async () => {
    await _sodium.ready;
    sodium = _sodium;
  });
  beforeEach(async () => {});
  it(' is proof that a primary can be succeeded by a recovery', async () => {
    const primary = await katra.new_keypair();
    const recovery = await katra.new_keypair();
    const claim = await katra.identity_continuity_claim({
      primary,
      recovery
    });
    expect(claim.message).toBe(`${primary.publicKey} <- ${recovery.publicKey}`);
    const claim_was_signed_by_primary = sodium.crypto_sign_verify_detached(
      sodium.from_hex(claim.primary_attestation),
      claim.message,
      sodium.from_hex(primary.publicKey)
    );
    const claim_was_signed_by_recovery = sodium.crypto_sign_verify_detached(
      sodium.from_hex(claim.recovery_attestation),
      claim.message,
      sodium.from_hex(recovery.publicKey)
    );
    expect(claim_was_signed_by_primary && claim_was_signed_by_recovery);
  });
});
