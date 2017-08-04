scrypt
======

A simple D library for encrypting passwords using scrypt.

## Dependencies

 * [libscrypt](https://github.com/technion/libscrypt)

### Ubuntu dependancy install

```
    sudo apt update;
    sudo apt install scrypt libscrypt-dev;
```

### OSX dependancy install

Homebrew installs libscrypt just fine, however you need to symlink the .dylib file to a .so file to make this work.

For me it was simply a matter of running:

```
    brew install libscrypt
    cd /usr/local/opt/libscrypt/lib
    ln -s libscrypt.0.dylib libscrypt.so.0
```

## Example snipets

see unittest block for more detailed usage 

### Bassic usage snipets

#### Generate 

```
    import scrypt;
    ...
    ...
    SodiumChloride salt = new SodiumChloride();	
    string password = "password";
    auto L = 256; //SCRYPT_OUTPUTLEN_DEFAULT;
    auto N = SCRYPT_N_DEFAULT;
    auto r = SCRYPT_R_DEFAULT;
    auto p = SCRYPT_P_DEFAULT;

    // with default values 
    ubyte[] hash_password = scrypt.generatePassword(password, salt.cl);
    // or with custom values
    //ubyte[] hash_password = scrypt.crypto_scrypt(password, salt.cl, N, r, p, L);

    // mythical method to store your values to a database.
    //db.save(scrypt.to_hex(hash_password),salt.na); 
    ...
```

#### Check password against saved hash

```
    import scrypt;
    ...
    ...
    // retrive your saved hex.
    //auto hex = db.gethex(); // mythical method get your values you stored. 
    
    // convert back to a ubyte array.
    ubyte[] hash = scrypt.hex_to_ubyteArray(hex);

    // check if passwords match. 
    if (scrypt.checkPassword(hash, password_entered)) {
        // passwords match Success!
    }
    // if using custom parameters
    //if (scrypt.checkPassword(hash, password_entered ,N, r, p, L) ) {
    // passwords match, Success!
    //}
    ...
```


