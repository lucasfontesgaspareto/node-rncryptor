const crypto = require('crypto');

const settings = {
	saltLength: 8,
	ivLength: 16,
	pbkdf2: {
		iterations: 10000,
		keyLength: 32
	},
	hmac: {
		length: 32
	}
};

/**
 *
 * @name decrypt Decrypt a AES-256-CBC text encrypted
 * @param {string} text Base64 String
 * @param {string} password Passsword
 */
const decrypt = (text, password) => {
	const { iv, cipherText, key } = extract(text, password);

	const hexIv = Buffer.from(iv, 'hex');
	const encryptedText = Buffer.from(cipherText, 'hex');
	const decipher = crypto.createDecipheriv(
		'aes-256-cbc',
		Buffer.from(key),
		hexIv
	);

	let decrypted = decipher.update(encryptedText);
	decrypted = Buffer.concat([decrypted, decipher.final()]);

	return decrypted.toString();
};

/**
 *
 * @name encrypt Encrypt a text with AES-256-CBC
 * 
 * 
 * Byte:     |    0    |    1    |      2-9       |  10-17   | 18-33 | <-      ...     -> | n-32 - n |
 * 
 * Contents: | version | options | encryptionSalt | HMACSalt |  IV   | ... ciphertext ... |   HMAC   |
 * 
 * 
 * @param {string} text Base64 String
 * @param {string} password Passsword
 * @param {object} config
 * @param {string} config.optionsFromEncryptedSource
 * @param {string} config.version
 * @param {string} config.options
 * @param {string} config.salt
 * @param {string} config.hmacSalt
 * @param {string} config.iv
 * @param {string} config.hmac
 * @param {string} config.key
 */

const encrypt = (text, password, config = {}) => {
	let source = {}

	if (config.optionsFromEncryptedSource) {
		source = extract(config.optionsFromEncryptedSource, password);
	}

	const { version, options, salt, hmacSalt, iv, hmac, key } = config.optionsFromEncryptedSource ? source : config

	const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);

 	let encrypted = cipher.update(text);
 	encrypted = Buffer.concat([encrypted, cipher.final()]);
	
 	return Buffer.concat([version, options, salt, hmacSalt, iv, encrypted, hmac]).toString('base64');
};

/**
 *
 * @name extract Extract informations about AES-256-CBC from RNCryptor base64
 * @param {string} text Base64 String
 * @param {string} password Passsword
 * @param {object} config Config behavor
 * @param {boolean} config.hex If true return hexadecimal values
 * @param {boolean} config.base64 If true return base64 values
 */
const extract = (text, password, config = {}) => {
	let offset = 0;
	const data = Buffer.from(text, 'base64');
	
	const version = data.slice(offset, offset + 1);
	offset += version.length;

	const options = data.slice(offset, offset + 1);
	offset += options.length;

	const salt = data.slice(offset, offset + settings.saltLength);
	offset += salt.length;

	const hmacSalt = data.slice(offset, offset + settings.saltLength);
	offset += hmacSalt.length;

	const iv = data.slice(offset, offset + settings.ivLength);
	offset += iv.length;

	const hmac = data.slice(data.length - settings.hmac.length);

	const cipherTextLength = data.length - offset - hmac.length;
	const cipherText = data.slice(offset, offset + cipherTextLength);
	
	const key = crypto.pbkdf2Sync(
		password,
		salt,
		settings.pbkdf2.iterations,
		settings.pbkdf2.keyLength,
		'SHA1'
	);

	if (config.hex) {
		return {
			version: Buffer.from(version).toString('hex'),
			options: Buffer.from(options).toString('hex'),
			salt: Buffer.from(salt).toString('hex'),
			hmacSalt: Buffer.from(hmacSalt).toString('hex'),
			iv: Buffer.from(iv).toString('hex'),
			hmac: Buffer.from(hmac).toString('hex'),
			cipherText: Buffer.from(cipherText).toString('hex'),
			key: Buffer.from(key).toString('hex')
		}
	}

	if (config.base64) {
		return {
			version: Buffer.from(version).toString('base64'),
			options: Buffer.from(options).toString('base64'),
			salt: Buffer.from(salt).toString('base64'),
			hmacSalt: Buffer.from(hmacSalt).toString('base64'),
			iv: Buffer.from(iv).toString('base64'),
			hmac: Buffer.from(hmac).toString('base64'),
			cipherText: Buffer.from(cipherText).toString('base64'),
			key: Buffer.from(key).toString('base64')
		}
	}

	return {
		version,
		options,
		salt,
		hmacSalt,
		iv,
		hmac,
		cipherText,
		key
	}
}

module.exports = {
	decrypt,
	encrypt,
	extract
};