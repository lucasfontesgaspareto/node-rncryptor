# node-rncryptor

> My awesome module

## Install

```
$ npm install node-rncryptor
```

## Usage

```js
const RNCryptor = require('node-rncryptor');
RNCryptor.encrypt('text', 'password', { optionsFromEncryptedSource: '', iv: '', key: '' });
//=> 'das90d9012o21sj21is21iw9012iw'
```

## API

### encrypt(text, password, options?)

#### text

Type: `string`

Lorem ipsum.

#### password

Type: `string`

Lorem ipsum.

#### options

Type: `object`

##### optionsFromEncryptedSource

Type: `string`

Allows to encrypt using options from a existing RNCryptor string

### decrypt(text, password)

#### text

Type: `string`

Lorem ipsum.

#### password

Type: `string`

Lorem ipsum.
