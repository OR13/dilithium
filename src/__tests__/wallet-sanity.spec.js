

const _sodium = require('libsodium-wrappers');
let sodium;

const RPC_HOST = 'http://localhost:8545';

const {
  getWeb3,
  sendWei,
  ed25519_keypair_to_curve25519_keypair,
  keypair_to_hex,
  getWalletFromPrivateKey,
  getWalletFromMnemonic
} = require('../lib');

describe('crypto-sanity', () => {
  beforeAll(async () => {
    await _sodium.ready;
    sodium = _sodium;
  });
  beforeEach(async () => {});


  const testWallet = async walletGenerator => {
    const FUND_AMOUNT = '500000000000013';
    const TRANSFER_AMOUNT = '80000000000013';
    // get web3 with unlocked testrpc accounts
    let web3 = await getWeb3(RPC_HOST);
    const defaultAccounts = await web3.eth.getAccounts();
    // create a new wallets
    const wallet1 = walletGenerator(sodium);
    const wallet2 = walletGenerator(sodium);
    // get wallet addresses
    const wallet1_address = '0x' + wallet1.getAddress().toString('hex');
    const wallet2_address = '0x' + wallet1.getAddress().toString('hex');
    // confirm wallet balances are 0
    let wallet1_balance = await web3.eth.getBalance(wallet1_address);
    let wallet2_balance = await web3.eth.getBalance(wallet2_address);
    expect(wallet1_balance).toBe('0');
    expect(wallet2_balance).toBe('0');
    // fund wallet from unlocked testrpc account
    let txhash = await sendWei(
      web3,
      defaultAccounts[0],
      wallet1_address,
      FUND_AMOUNT
    );
    // confirm wallet balance has been updated
    wallet1_balance = await web3.eth.getBalance(wallet1_address);
    expect(wallet1_balance).toBe(FUND_AMOUNT);
    // get web3 from wallet
    web3 = await getWeb3(RPC_HOST, wallet1);
    const walletAccounts = await web3.eth.getAccounts();
    expect(walletAccounts[0].toLowerCase()).toBe(wallet1_address);
    // transfer from wallet1 to wallet2
    txhash = await sendWei(
      web3,
      wallet1_address,
      wallet2_address,
      TRANSFER_AMOUNT
    );
    wallet2_balance = await web3.eth.getBalance(wallet2_address);
    // confirm wallet2 balance
    expect(wallet2_balance).toBe(TRANSFER_AMOUNT);
  };

  it('wallet from libsodium private key', async () => {
    await testWallet(getWalletFromPrivateKey);
  });

  it('wallet from mnemonic', async () => {
    await testWallet(getWalletFromMnemonic);
  });
});
