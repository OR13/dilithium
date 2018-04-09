const Ganache = require('ganache-core');
const tipal = require('../tipal');
const katra = require('../../katra');

const plaintext_id = {
  ethereum_address: '0xfc94fd019037b17f0e5eaece855554271b83a137',
  primary: {
    publicKey:
      '4bfa8302a85db1cf6530cd8e5a0d59cc768eaa79550e3c41e92941c3ee293e76',
    privateKey:
      '926ae5796df9a9e2a3f06bf02998ece907ee4202c3d526182bb0fe89c56f9c8c4bfa8302a85db1cf6530cd8e5a0d59cc768eaa79550e3c41e92941c3ee293e76',
    keyType: 'ed25519'
  },
  recovery: {
    publicKey:
      '41bc9923e0d49e4605c97f392c1941f9b822bfc96ae80b3afc12b14c2e525252',
    privateKey:
      'd34f7533fe759f072b6f584522b8b318e6cddb403b19afab74295fd8752be93841bc9923e0d49e4605c97f392c1941f9b822bfc96ae80b3afc12b14c2e525252',
    keyType: 'ed25519'
  },
  history: [
    {
      message:
        '4bfa8302a85db1cf6530cd8e5a0d59cc768eaa79550e3c41e92941c3ee293e76 <- 41bc9923e0d49e4605c97f392c1941f9b822bfc96ae80b3afc12b14c2e525252',
      primary_attestation:
        '7c6e09d9d91e5b945b8fa8a925ef2a2cab730633d86554f64db4a1c2d26c2e707ac4af5f45adeb388e00e6fda0f4f4abda1db211f9e714a20c9026a4b2ab260c',
      recovery_attestation:
        '7df74322d1604fa3ba80e1f16ae8eea89aee340c16afe98064ece689279c385d5ae8bc4e2fb696a2a2599d3af3af40d6edb5ea323567924f3b8fd133cd18840a'
    },
    {
      message:
        '403fbfcfe8f40ff456a277822a909b9c81dbf4092e72628bbe82019cc9be2aec <- 4bfa8302a85db1cf6530cd8e5a0d59cc768eaa79550e3c41e92941c3ee293e76',
      primary_attestation:
        '05e4e8a3410ddce1932cbfb69119327c9553e40477d9846d5a867c51d7389dff20673bdda53c81c4977b3ff49a4fc3ee13222052e5a3e26deb9b94f90b7b3c04',
      recovery_attestation:
        '48f4cb541a7d4e06388e987dc5d02c3bfdd958f28cb9cc54bdab946118a22969fef15499954852d605fa6fd827defc840de5f0c263dee47ec562b2ec9d39ac08'
    }
  ]
};

const get_server = async () => {
  return new Promise((resolve, reject) => {
    const server = Ganache.server();
    server.listen('8545', (err, blockchain) => {
      resolve(server);
    });
  });
};

describe('tipal.get_web3_from_private_key', () => {
  it('works as expected', async () => {
    const server = await get_server();
    const { web3 } = tipal.get_web3({
      provider_url: 'http://localhost:8545'
    });
    let accounts = await web3.eth.getAccounts();
    // console.log(accounts);
    expect(accounts.length).toBe(10);
    let balance = await web3.eth.getBalance(plaintext_id.ethereum_address);
    // console.log(balance);
    let txhash = await tipal.send_wei(
      web3,
      accounts[0],
      plaintext_id.ethereum_address,
      420000050000000
    );
    const wallet_web3 = await tipal.get_web3_from_private_key({
      private_key: plaintext_id.primary.privateKey,
      provider_url: 'http://localhost:8545'
    });
    let balance2 = await wallet_web3.web3.eth.getBalance(
      plaintext_id.ethereum_address
    );
    // console.log(balance2);
    let txhash2 = await tipal.send_wei(
      wallet_web3.web3,
      plaintext_id.ethereum_address,
      accounts[2],
      50000000
    );

    expect(txhash2).toBeDefined();
    // server.close();
  });
});
