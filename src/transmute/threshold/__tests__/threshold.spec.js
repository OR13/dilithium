const thresholdLib = require('../thresholdLib');

const { loadObject, saveObject } = require('../../../lib');

describe('symmetric', () => {
  beforeAll(async () => {});
  beforeEach(async () => {});

  const args = {
    key: '7ccf6196ae058dac1d02ccd0edd7e0c888e8d2aad609800cab5a0936b6c41018',
    share_num: 10,
    share_threshold: 5
  };

  const shares = [
    '801ee73990bfe33dc992ce1ca87f77646eae1de7c61fd4726eb9419109f16e0b8dacf86f680da2925fe941ce10a1ed4f14f',
    '80252250fad4eb9b3a4136a3d1276479781411055d1d49b28599b4c7ed3a5697b0ff4ff4f38ee78873785259c114a507e91',
    '803d9ae660836eec9ba0d0826bb234294f5047da22ce0940b643467ed321eff95ae88e96f13678c300d5d4a52a1b3be9bfb',
    '804dbe21e3ae2e9110924117f5fa9cb2ea775a25ccfaa82948502dee9ce7c7abb646138b623584495b67d7f33b0e6336892',
    '80576bb9df22f9f3ea5a4dd693cb58aeb2902a60704b67328c35f658a421aac70fbbc5b8a0f6da65cce2acf0f83b51d914b',
    '8068654c28ee857fbe1ba178420a633ababc6ba6bd8cf4e0587a90d19d40ea5f952d8c80bb93cdb028338558b83a80426ee',
    '8074ef5b1e8a34572ca0858436d18012bba69c2da19b4f231bbd28635f628d2847e3ed333948cedd93388cc913caad4db0a',
    '8089353a7d94c080d1d0dfee4b5f625f4a80ca388f44deccf3be41828a3d8b13c1c44d6ffbaea9d5e9128ecf8751b5e509a',
    '809e54fb17b5cbf9876639d1a3d385e8d8c590b1fdbbe71228d82791345709bf0f6bd71ab8c2ce51e7611f1ff7f2169c13b',
    '80ae33b782287a3750c17e177d48bc70f2732d4b64e7583d2c68c3f0bf60c544bc79ca9a21807b21e8e6170832a6c27fe17'
  ];

  it('threshold-shatter-key', async () => {
    let { hash, shares } = await thresholdLib['threshold-shatter-key'](args);
    expect(shares.length).toEqual(args.share_num);
  });

  it('threshold-recover-key', async () => {
    let key = await thresholdLib['threshold-recover-key'](shares);
    expect(key).toEqual(args.key);
  });
});
