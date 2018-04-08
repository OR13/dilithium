const asymmetricLib = require('../asymmetricLib');

const { keypair_to_hex } = require('../../../lib');

const _sodium = require('libsodium-wrappers');
let sodium;

const message = 'hello';

describe('asymmetric', () => {
  beforeAll(async () => {
    await _sodium.ready;
    sodium = _sodium;
  });
  beforeEach(async () => {});

  it('asymmetric-sign', async () => {
    const keypair = keypair_to_hex(sodium, sodium.crypto_sign_keypair());
    let result = await asymmetricLib['asymmetric-sign']({
      message,
      privateKey: keypair.privateKey
    });
    // console.log(result);
  });

  it('asymmetric-verify', async () => {
    const keypair = keypair_to_hex(sodium, sodium.crypto_sign_keypair());
    let result = await asymmetricLib['asymmetric-sign']({
      message: message,
      privateKey: keypair.privateKey
    });
    let recovered_message = await asymmetricLib['asymmetric-verify']({
      message: result,
      publicKey: keypair.publicKey
    });
    expect(recovered_message).toBe(message);
  });
});
