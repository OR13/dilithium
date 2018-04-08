
rm -rf ./recovery-shares transmute-id.json

npm run dilithium -- identity-create bob PASSWORD

npm run dilithium -- identity-recover PASSWORD PASSWORD ./recovery-shares/

npm run dilithium -- identity-recover PASSWORD PASSWORD ./recovery-shares/

npm run dilithium -- identity-recover PASSWORD PASSWORD ./recovery-shares/