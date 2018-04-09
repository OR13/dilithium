
rm -rf katra.json ./recovery-shares

node ./src/main katra create PASSWORD

node ./src/main.js fund-from-default ./katra.json 13370000000000000
node ./src/main.js fund-from-default ./katra.json 13370000000000000
node ./src/main.js fund-from-default ./katra.json 13370000000000000

node ./src/main.js send-wei PASSWORD ./katra.json  0xa62f5Ca71Fb20cbA4d6745B4dAaF3904f8380d01 420000050000000

node ./src/main.js change-password PASSWORD PASSWORD2 ./katra.json 