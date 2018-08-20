const fse = require('fs-extra');

const writeFile = async (filePath, fileData) => {
  try {
    await fse.outputFile(filePath, fileData);
  } catch (err) {
    console.error(err);
  }
};

const readFile = async filePath => {
  try {
    const data = await fse.readFile(filePath);
    return data;
  } catch (err) {
    console.error(err);
  }
};

module.exports = {
  writeFile,
  readFile
};
