const katra = require('../katra');

describe('katra.verify_history', () => {
  //   it('handles the empty case', async () => {
  //     const primary = await katra.new_keypair();
  //     const recovery = await katra.new_keypair();
  //     let current_id = await katra.generate_id({
  //       primary,
  //       recovery
  //     });
  //     const is_history_valid = await katra.verify_history(current_id);
  //     expect(is_history_valid);
  //   });

  it('handles 1 recovery', async () => {
    const primary = await katra.new_keypair();
    const recovery = await katra.new_keypair();
    let current_id = await katra.generate_id({
      primary,
      recovery
    });
    // recover once
    current_id = await katra.recover_id({
      compromised_id: current_id
    });
    const is_history_valid = await katra.verify_history(current_id);
    expect(is_history_valid);
  });

  it('handles n=3 recovery', async () => {
    const primary = await katra.new_keypair();
    const recovery = await katra.new_keypair();
    let current_id = await katra.generate_id({
      primary,
      recovery
    });
    let count = 0;
    while (count < 3) {
      current_id = await katra.recover_id({
        compromised_id: current_id
      });
      count++;
    }
    const is_history_valid = await katra.verify_history(current_id);
    expect(is_history_valid);
    //   console.log(current_id)
  });
});
