
# SYMMETRIC 

rm -rf ./store/*.json
rm -rf ./test-data/plainText.txt.*

npm run dilithium -- symmetric-create-key lockbox-key PASSWORD
npm run dilithium -- symmetric-recover-key lockbox-key PASSWORD
npm run dilithium -- symmetric-encrypt ./test-data/plainText.txt 7ccf6196ae058dac1d02ccd0edd7e0c888e8d2aad609800cab5a0936b6c41018
npm run dilithium -- symmetric-decrypt ./test-data/plainText.txt.encrypted.json 7ccf6196ae058dac1d02ccd0edd7e0c888e8d2aad609800cab5a0936b6c41018

# # THRESHOLD 

rm -rf ./store/*.json
rm -rf ./test-data/plainText.txt.*

npm run dilithium -- threshold-shatter-key facdc868d0ddaa8fe2df27860cc470ff138df46acf50e0b6ff429d1941402873 10 5
npm run dilithium -- threshold-recover-key shattered-lockbox-key ./store
