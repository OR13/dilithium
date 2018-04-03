const symmetricLib = require('../symmetricLib');
const _sodium = require('libsodium-wrappers');
let sodium;

describe('symmetric', () => {
  beforeAll(async () => {
    await _sodium.ready;
    sodium = _sodium;
  });
  beforeEach(async () => {});

  const args = {
    name: 'lockbox-key',
    password: 'open sesame'
  };

  it('symmetric-create-key', async () => {
    let { key, salt } = await symmetricLib['symmetric-create-key'](args);
    expect(salt.length).toBe(32);
  });

  it('symmetric-recover-key', async () => {
    let { key, salt } = await symmetricLib['symmetric-create-key'](args);
    let recovered_key = await symmetricLib['symmetric-recover-key']({
      salt: salt,
      password: args.password
    });
    expect(recovered_key).toBe(key);
  });

  it('symmetric-encrypt', async () => {
    let plainText = '123';
    let key =
      '7ccf6196ae058dac1d02ccd0edd7e0c888e8d2aad609800cab5a0936b6c41018';
    let { nonce, encrypted } = await symmetricLib['symmetric-encrypt']({
      data: plainText,
      key
    });
    expect(nonce.length).toEqual(48);
    expect(encrypted.length).toEqual(38);
  });

  it('symmetric-decrypt', async () => {
    let plainText = '123';
    let key =
      '7ccf6196ae058dac1d02ccd0edd7e0c888e8d2aad609800cab5a0936b6c41018';
    let { nonce, encrypted } = await symmetricLib['symmetric-encrypt']({
      data: plainText,
      key
    });
    let decrypted = await symmetricLib['symmetric-decrypt']({
      data: encrypted,
      nonce,
      key
    });
    expect(decrypted).toBe(plainText);
  });
});
