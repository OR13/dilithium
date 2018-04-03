# Experimental Crypto

DO NOT USE.

```
npm i
npm run test
```


TODO:

- tighten up asymmetric tests... make sure everything is hex...
- document usage
- normalize ethereum env


### Concept

The idea is:

user provides a name and password.system generates a salt and derives a primary_key from the password and the salt.

system generates 2 ed25519 key pairs: primary and recovery.

system signs primary public key with recovery secret (recovery key claims primary key).

system encrypts primary keypair with primary_key (derived from password, this is just like sigmate)

system generates a recovery key, encrypts recovery_keypair with it. 

system uses shamir secret sharing to shatter recovery key, now recovery_keypair cannot be recovered without threshold shares (so long as user does not store/retain or persist the recovery key)

system saves ciphertext of keys, salts, claims and public information to transmute-id.json

user can use their password to unlock primary keypair, or use recovery-shares to upgrade their identity.

currently, no support for primary_key password change exists, but thats easy to add.

### References
- https://github.com/grempe/secrets.js
- https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html
- https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html
- https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html