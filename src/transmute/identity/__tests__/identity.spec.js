const identityLib = require('../identityLib');

describe('identity', () => {
  beforeAll(async () => {});
  beforeEach(async () => {});

  it('identity-create', async () => {
    let args = {
      name: 'billy',
      password: 'weak'
    };
    let result = await identityLib['identity-create'](args);
    // console.log(result);
  });
});
