const symmetricLib = require('../symmetricLib');
const { loadObject, saveObject } = require('../../../lib');

describe('symmetric', () => {
  beforeAll(async () => {});
  beforeEach(async () => {});

  const args = {
    name: 'lockbox-key',
    password: 'open sesame'
  };

  it('symmetric-create-key', async () => {
    let { name, salt } = await symmetricLib['symmetric-create-key'](args);
    expect(name).toEqual(args.name);
    expect(salt.length).toBe(32);
  });

  it('symmetric-recover-key', async () => {
    let stored = await symmetricLib['symmetric-create-key'](args);
    await saveObject({
      id: stored.name,
      salt: stored.salt
    });
    let recovered = await symmetricLib['symmetric-recover-key'](
      args.name,
      args.password
    );
    expect(recovered.name).toEqual(args.name);
    expect(recovered.salt).toEqual(stored.salt);
    expect(recovered.key).toBe(stored.key);
  });

  it('symmetric-encrypt', async () => {
    let plainText = '123';
    let key =
      '7ccf6196ae058dac1d02ccd0edd7e0c888e8d2aad609800cab5a0936b6c41018';
    let { nonce, encrypted } = await symmetricLib['symmetric-encrypt'](
      plainText,
      key
    );
    expect(nonce.length).toEqual(48);
    expect(encrypted.length).toEqual(38);
  });

  it('symmetric-decrypt', async () => {
    let plainText = '123';
    let key =
      '7ccf6196ae058dac1d02ccd0edd7e0c888e8d2aad609800cab5a0936b6c41018';
    let { nonce, encrypted } = await symmetricLib['symmetric-encrypt'](
      plainText,
      key
    );
    let decrypted = await symmetricLib['symmetric-decrypt'](
      encrypted,
      nonce,
      key
    );
    expect(decrypted).toBe(plainText);
  });
});
