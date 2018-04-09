
rm -rf katra.json ./recovery-shares


ORIGINAL_INTEGRITY=$(node ./src/main katra create PASSWORD | jq '.integrity')
INTEGRITY_MATCH=$(node ./src/main katra verify ./katra.json $ORIGINAL_INTEGRITY | jq '.integrity')

echo 'INTEGRITY_MATCH ' $INTEGRITY_MATCH

COMPROMISED_INTEGRITY=$(node ./src/main katra recover PASSWORD PASSWORD2 ./katra.json ./recovery-shares  | jq '.integrity')
RECOVERD_INTEGRITY=$(node ./src/main katra recover PASSWORD2 PASSWORD3 ./katra.json ./recovery-shares $COMPROMISED_INTEGRITY | jq '.integrity')

echo 'ORIGINAL_INTEGRITY ' $ORIGINAL_INTEGRITY
echo 'COMPROMISED_INTEGRITY ' $COMPROMISED_INTEGRITY
echo 'RECOVERD_INTEGRITY ' $RECOVERD_INTEGRITY


node ./src/main.js fund-from-default ./katra.json 13370000000000000

node ./src/main.js send-wei PASSWORD3 ./katra.json  0xa62f5Ca71Fb20cbA4d6745B4dAaF3904f8380d01 420000050000000
