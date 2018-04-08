
rm -rf ./recovery-shares transmute-id.json

npm run dilithium -- identity-create bob PASSWORD
npm run dilithium -- change-password PASSWORD PASSWORD2
npm run dilithium -- change-password PASSWORD2 PASSWORD3

