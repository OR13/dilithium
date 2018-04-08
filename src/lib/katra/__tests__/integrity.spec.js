const katra = require('../katra');
const secrets = require('secrets.js-grempe');

describe('katra.test_ciphertext_id_integrity', () => {
  it(' uses get_ciphertext_id_integrity to check ciphertext_id', async () => {
    const { ciphertext_id, shares } = {
      ciphertext_id: {
        id_password_salt: 'a6af01b584f53110757846840bc7abde',
        primary: {
          publicKey:
            'a234e1a04ea14bfa3567e71ff55116a411945f40680eb0311b5c474390b57aa8',
          privateKey: {
            nonce: '8fcb80913a4a63defb73c093a5a0fc6ec4cd711b6746f331',
            encrypted:
              '91f55df7eb203c239ba5e4e90b9d561caccee2b9f778e6001c4f3e590909add244f8b0c68040dc6d77d21d6c98fe19c98cdad85665333e791a94b96f0f1cd00de90b93baa1e6b3da802a64e5e68519654c3b248684ddd46b0271dc95495826653810972eeec81a83697524f3d179a6b78de02f26899f28993c827e31f17ba030891de2b5d373cef43863a7ac6c60dd6e6573'
          },
          keyType: 'ed25519'
        },
        recovery: {
          publicKey:
            '94e02ac4016d8a88a508bd10987824674dba6fce25491526d0271e20ee6c9798',
          privateKey: {
            nonce: 'be44f6360f0174cea8df16aa9535e5696156d4f2914431fd',
            encrypted:
              'dcc5be9f5a9c53573907e1241300b6972ffc776e58f20b9d50c5f877f871a920b62da6cf5a5ab5c86f79cda4936fd5afcbd7f5e7c783c14396fd22690175af7cfa94ec3a1f158d0b4fd627ae1c6b42e7fda3f3b3ffbfe235262946f4c5468cb3ae58cd0868db24ea7022c7292cfee3aa1940c2cf4d9920a77f2215a00dba1996bb650c419675812c39ede72c361451184b63'
          },
          keyType: 'ed25519'
        },
        history: [
          {
            message:
              'a234e1a04ea14bfa3567e71ff55116a411945f40680eb0311b5c474390b57aa8 <- 94e02ac4016d8a88a508bd10987824674dba6fce25491526d0271e20ee6c9798',
            primary_attestation:
              '853c2e1336b6bdf49a61e5874723b089c0e51d1ebb04788d5ecff029e81cc0d6b4bc3994e763c9f57169cc8bd9f6bc5ed54896bd7fa296ebbb487e6252266b01',
            recovery_attestation:
              '0badafd95c8c6e5a7923bd7a50429ad831b606ae52091f438b386e8e0a5bf0756293348fb45346bd2c33cd3db54fb269689ea11a07b328812e109e21b5249209'
          }
        ]
      },
      shares: [
        '801267b6a59274c13e6fdffb2039d50f376967180143d4c70db95bee09927d626123b70a73a47f3a19c9f0a311c6fa2aa96',
        '8024cf6d4b24e9826d1e7e3790627a0fbefe65de5f2167b41c64d91fe19bdf36f4d00de5579e6f5d6d7fb0bbbfb98a79852',
        '8036a8dbeeb69d435371a1ccb05baf008983db2c65b0f9da5cd057ff492cb1ba378e24ff0b372f7fbee2cff36a63ea47de5'
      ]
    };

    const integrity = await katra.get_ciphertext_id_integrity({
      ciphertext_id
    });

    expect(
      katra.test_ciphertext_id_integrity({
        ciphertext_id,
        integrity
      })
    );
  });
});
