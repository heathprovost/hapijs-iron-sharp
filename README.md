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

// simple example using string password and default settings

var token = Iron.Seal(plaintext, password, Iron.DEFAULTS);
var unsealed = Iron.Unseal(token, passwords, Iron.DEFAULTS);
Console.Writeline(unsealed);

//Prints {"foo":"bar"}
```

### Iron.Unseal

```C#
var unsealed = Iron.Unseal(token, passwords, Iron.DEFAULTS);
```
