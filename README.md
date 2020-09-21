# hapijs-iron-sharp
A mostly compatible .NET implementation of @hapijs/iron encapsulated tokens (encrypted and mac'ed objects)

## Differences

* You must serialize/deserialize your data yourself (@hapijs/iron does this for you).
* To ensure interoperability with @hapijs/iron in node, just make sure anything you seal can be cleanly parsed by `JSON.parse` and that your password matches as well at the settings for `ttl`, `timestampSkew`, and `localtimeOffset`.
* Password rotation is supported and is interoporable, but it implemented differently. See examples.
* Encryption\decryption uses `aes-256-cbc` and Hmac uses `sha256` exclusively, exactly as configured in @hapijs/iron default settings. 
* `aes-128-ctr` is not supported, nor is customizing algorithms settings like `iterations`, `minPasswordlength`, or `saltBits`.

## Examples

### Basics

```C#
var plaintext = "{\"foo\":\"bar\"}"; //anything serialized into JSON
var password = "my-really-secure-password-string"

var token = Iron.Seal(plaintext, password, Iron.DEFAULTS);
var unsealed = Iron.Unseal(token, password, Iron.DEFAULTS);

Console.WriteLine(unsealed);
//Prints {"foo":"bar"}
```
### Set TTL

```C#
var plaintext = "{\"foo\":\"bar\"}"; //anything serialized into JSON
var options = new IronOptions(ttl: (60 * 1000)); //1 minute in milliseconds
var password = "my-really-secure-password-string"

var token = Iron.Seal(plaintext, password, options);

//...wait until TTL expires

var unsealed = Iron.Unseal(token, password, options);

//Throws "Expired seal" exception
```

### Password Rotation

```C#
var plaintext = "{\"foo\":\"bar\"}"; //anything serialized into JSON
var password1 = new IronPassword(id: "foo", password: "my-really-secure-password-string");
var password2 = new IronPassword(id: "bar", password: "my-other-really-secure-password-string");
var token = Iron.Seal(plaintext, password1, Iron.DEFAULTS);

var unsealed = Iron.Unseal(token, password2, Iron.DEFAULTS); //Throws "Cannot find password foo" exception

//create array with both passwords in it and try again

var passwords = new IronPassword[] {password1, password2};
var unsealed = Iron.Unseal(token, passwords, Iron.DEFAULTS);
Console.WriteLine(unsealed);
//Prints {"foo":"bar"}

```
