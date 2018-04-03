
# ASYMMETRIC 

npm run dilithium -- asymmetric-create-key

# [info] created: {
#   "publicKey": "5f95001535b7e128d81e01748f021b27b1bf742ebb1d55a3e53624edd5891c4d",
#   "privateKey": "f7bb675637e4403d7a760695935d1769bb739ce11f012b1297242f5b90e3d368"
# }

# [info] created: {
#   "publicKey": "5f3cd89d846ba20579e946abdb97bad44f455684318c16757456954dffd6d850",
#   "privateKey": "d19020bbe2ae0875fb825c322684d57c6fd89279f986fec45c8ba82744f6a24e"
# }

npm run dilithium -- asymmetric-encrypt f7bb675637e4403d7a760695935d1769bb739ce11f012b1297242f5b90e3d368 5f3cd89d846ba20579e946abdb97bad44f455684318c16757456954dffd6d850 hello

# [info] encrypted: ewogICJub25jZSI6ICIzMWQ1Yjk0M2YzZTIzYmFkNGJhMDBkYWJjMTc3ZjA3MWFiN2NkNjIxN2EwMDBhZWIiLAogICJjaXBoZXJ0ZXh0IjogImIyNTVlNDI2M2Q3OWEzY2Q0ODViYzY3M2FmNzUzZGYzMzVkNjFiZDg3NSIKfQ==

npm run dilithium -- asymmetric-decrypt 5f95001535b7e128d81e01748f021b27b1bf742ebb1d55a3e53624edd5891c4d d19020bbe2ae0875fb825c322684d57c6fd89279f986fec45c8ba82744f6a24e ewogICJub25jZSI6ICIzMWQ1Yjk0M2YzZTIzYmFkNGJhMDBkYWJjMTc3ZjA3MWFiN2NkNjIxN2EwMDBhZWIiLAogICJjaXBoZXJ0ZXh0IjogImIyNTVlNDI2M2Q3OWEzY2Q0ODViYzY3M2FmNzUzZGYzMzVkNjFiZDg3NSIKfQ==

# [info] decrypted: hello

# SYMMETRIC 

rm -rf ./store/*.json
rm -rf ./test-data/plainText.txt.*

npm run dilithium -- symmetric-create-key lockbox-key PASSWORD
npm run dilithium -- symmetric-recover-key lockbox-key PASSWORD
npm run dilithium -- symmetric-encrypt ./test-data/plainText.txt 7ccf6196ae058dac1d02ccd0edd7e0c888e8d2aad609800cab5a0936b6c41018
npm run dilithium -- symmetric-decrypt ./test-data/plainText.txt.encrypted.json 7ccf6196ae058dac1d02ccd0edd7e0c888e8d2aad609800cab5a0936b6c41018

# THRESHOLD 

rm -rf ./store/*.json
rm -rf ./test-data/plainText.txt.*

npm run dilithium -- threshold-shatter-key facdc868d0ddaa8fe2df27860cc470ff138df46acf50e0b6ff429d1941402873 10 5
npm run dilithium -- threshold-recover-key shattered-lockbox-key ./store
