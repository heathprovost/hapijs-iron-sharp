# hapijs-iron-sharp
A mostly compatible .NET implementation of @hapijs/iron encapsulated tokens (encrypted and mac'ed objects)

# Differences

* You must serialize your data prior to sealing into a token.
* Likewise, you must deserialize your data after unsealing it.
* If you want to ensure that your tokens can be properly handled in node by @hapijs/iron, just make sure anything you seal can be cleanly parsed by `JSON.parse`.
* Passwords must be provided as a simple string (`password.Secret`, `password.Specific`, and `password.Hash` objects are not supported)
* Encryption\decryption uses `aes-256-cbc` and Hmacs use `sha256` exclusively, exactly as configured in @hapijs/iron default settings. 
* `aes-128-ctr` is not supported, nor is customizing algorithms settings.
* The only options you can change are Ttl, timestampSkew, and localtimeOffset, everything else is hardcoded as per @hapijs/iron default settings.
