scrypt
======

A simple D library for encrypting passwords using scrypt.

## Dependencies

 * [libscrypt](https://github.com/technion/libscrypt)

**Note for OSX**

Homebrew installs libscrypt just fine, however you need to symlink the .dylib file to a .so file to make this work.

For me it was simply a matter of running:

    brew install libscrypt
    cd /usr/local/opt/libscrypt/lib
    ln -s libscrypt.0.dylib libscrypt.so.0

And away it went.
