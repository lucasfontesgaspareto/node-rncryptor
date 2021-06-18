const { decrypt, encrypt, extract } = require('./index.js');
const config = require('./config')

test('encrypt', () => {
  expect(encrypt(config.decrypted, config.password, { optionsFromEncryptedSource: config.encrypted })).toBe(config.encrypted);
});

test('decrypt', () => {
  expect(decrypt(config.encrypted, config.password)).toBe(config.decrypted);
});

test('extract', () => {
  expect(extract(config.encrypted, config.password)).toMatchObject({
		version: Buffer.from(['03'].join(''), 'hex'),
		options: Buffer.from(['01'].join(''), 'hex'),
		salt: Buffer.from(['64', '6f', '26', '74', '99', '61', '8a', '0b'].join(''), 'hex'),
		hmacSalt: Buffer.from(['e8','1f','84','35','bd','91','89','ab'].join(''), 'hex'),
		iv: Buffer.from(['88','18','d2','99','6f','a3','69','04','05','5f','f9','c4','ec','05','25','7c'].join(''), 'hex'),
		hmac: Buffer.from(['1d','32','20','c8','f5','82','a7','31','a7','31','9d','10','18','68','80','c5','79','1e','6f','9f','61','af','61','e6','6c','65','d7','43','9b','0e','52','81'].join(''), 'hex'),
		cipherText: Buffer.from(['49','fd','f2','7d','c5','c1','e9','13','b5','9b','75','fb','f2','0b','3d','51'].join(''), 'hex'),
		key: Buffer.from(['58','09','f1','48','45','fe','ca','be','d0','04','a0','f1','80','64','0b','62','d2','90','c1','f1','47','73','f6','2f','9b','c1','48','9c','13','ec','1c','97'].join(''), 'hex'),
	});
});

test('extract with hex', () => {
  expect(extract(config.encrypted, config.password, { hex: true })).toMatchObject({
		version: '03',
		options: '01',
		salt: '646f267499618a0b',
		hmacSalt: 'e81f8435bd9189ab',
		iv: '8818d2996fa36904055ff9c4ec05257c',
		hmac: '1d3220c8f582a731a7319d10186880c5791e6f9f61af61e66c65d7439b0e5281',
		cipherText: '49fdf27dc5c1e913b59b75fbf20b3d51',
		key: '5809f14845fecabed004a0f180640b62d290c1f14773f62f9bc1489c13ec1c97'
	});
});

test('extract with base64', () => {
  expect(extract(config.encrypted, config.password, { base64: true })).toMatchObject({
		version: 'Aw==',
		options: 'AQ==',
		salt: 'ZG8mdJlhigs=',
		hmacSalt: '6B+ENb2Rias=',
		iv: 'iBjSmW+jaQQFX/nE7AUlfA==',
		hmac: 'HTIgyPWCpzGnMZ0QGGiAxXkeb59hr2HmbGXXQ5sOUoE=',
		cipherText: 'Sf3yfcXB6RO1m3X78gs9UQ==',
		key: 'WAnxSEX+yr7QBKDxgGQLYtKQwfFHc/Yvm8FInBPsHJc='
	});
});