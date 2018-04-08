const katra = require('../katra');
const secrets = require('secrets.js-grempe');

describe('katra.plaintext_to_ciphertext_and_shares', () => {
  it(' is reversable with ciphertext_and_shares_to_plaintext', async () => {
    const { primary, recovery, password } = {
      primary: {
        publicKey:
          'a234e1a04ea14bfa3567e71ff55116a411945f40680eb0311b5c474390b57aa8',
        privateKey:
          'aed7a9a2200380078a71f95fa36a6ff397e33290597d0397f2f0d7e608394f78a234e1a04ea14bfa3567e71ff55116a411945f40680eb0311b5c474390b57aa8',
        keyType: 'ed25519'
      },
      recovery: {
        publicKey:
          '94e02ac4016d8a88a508bd10987824674dba6fce25491526d0271e20ee6c9798',
        privateKey:
          '4a0c0468780e20aeda824330e0bf245a7a7a5c33e0ea2013c250c0eac46afe5994e02ac4016d8a88a508bd10987824674dba6fce25491526d0271e20ee6c9798',
        keyType: 'ed25519'
      },
      password: 'Tuvok-1-4-9-4-Lambda'
    };
    const plaintext_id = await katra.generate_id({ primary, recovery });
    const {
      ciphertext_id,
      shares
    } = await katra.plaintext_to_ciphertext_and_shares({
      plaintext_id,
      password
    });
    const plaintext_id2 = await katra.ciphertext_and_shares_to_plaintext({
      password,
      ciphertext_id,
      shares
    });
    expect(plaintext_id).toEqual(plaintext_id2);
  });
});
