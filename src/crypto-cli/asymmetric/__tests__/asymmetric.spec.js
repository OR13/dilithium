const asymmetricLib = require('../asymmetricLib');

describe('asymmetric', () => {
  beforeAll(async () => {});
  beforeEach(async () => {});

  // it('asymmetric-create-keypair', async () => {
  //   let keypair = await asymmetricLib['asymmetric-create-keypair']();
  //   expect(keypair.publicKey).toBeDefined();
  //   expect(keypair.privateKey).toBeDefined();
  // });

  // it('asymmetric-encrypt', async () => {
  //   let sender = await asymmetricLib['asymmetric-create-keypair']();
  //   let receiver = await asymmetricLib['asymmetric-create-keypair']();
  //   let result = await asymmetricLib['asymmetric-encrypt']({
  //     payload: 'hello',
  //     senderPrivateKey: sender.privateKey,
  //     recipientPublicKey: receiver.publicKey
  //   });
  //   expect(result.nonce).toBeDefined();
  //   expect(result.ciphertext).toBeDefined();
  // });
  // it('asymmetric-decrypt', async () => {
  //   let sender = await asymmetricLib['asymmetric-create-keypair']();
  //   let receiver = await asymmetricLib['asymmetric-create-keypair']();
  //   let message = 'hello';
  //   let result = await asymmetricLib['asymmetric-encrypt']({
  //     payload: message,
  //     senderPrivateKey: sender.privateKey,
  //     recipientPublicKey: receiver.publicKey
  //   });
  //   let result2 = await asymmetricLib['asymmetric-decrypt']({
  //     payload: result,
  //     senderPublicKey: sender.publicKey,
  //     recipientPrivateKey: receiver.privateKey
  //   });
  //   // console.log(result);
  //   // console.log(result2);
  //   expect(result2).toEqual(message);
  // });

  it('asymmetric-sign', async () => {
    let keypair = await asymmetricLib['asymmetric-create-keypair']();
    let args = {
      message: 'hello',
      privateKey: keypair.privateKey
    };
    let result = await asymmetricLib['asymmetric-sign'](args);
    console.log(result);
  });
});
