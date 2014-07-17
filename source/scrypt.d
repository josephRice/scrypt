module scrypt;

import std.string : indexOf;
import std.exception : enforce;
import std.digest.digest : toHexString;
import std.uuid : randomUUID;
import std.algorithm : splitter;
import std.array: array;
import std.conv: to;


ulong SCRYPT_N_DEFAULT = 16384;
uint SCRYPT_R_DEFAULT = 8;
uint SCRYPT_P_DEFAULT = 1;
size_t SCRYPT_OUTPUTLEN_DEFAULT = 128;

ubyte[] generatePassword(string password) {
    return generatePassword(password, randomUUID.data);
}

ubyte[] generatePassword(string password, ubyte[] salt) {
    ubyte[] outpw = new ubyte[SCRYPT_OUTPUTLEN_DEFAULT];
    libscrypt_scrypt(cast(ubyte*)password.ptr, password.length, cast(ubyte*)salt.ptr, salt.length, SCRYPT_N_DEFAULT, SCRYPT_R_DEFAULT, SCRYPT_P_DEFAULT, outpw.ptr, outpw.length);

    return outpw ~ salt;
}

bool checkPassword(ubyte[] hash, string password) {
    auto salt = hash[SCRYPT_OUTPUTLEN_DEFAULT..$];
    return generatePassword(password, salt) == hash;
}

unittest {
    import std.stdio;

    writeln("*** test: generatePassword");
    auto input = "test";
    auto hash = generatePassword(input);
    writeln("*** > input: " ~ input);
    writeln("*** > scrypt: " ~ to!string(hash));
    assert(hash !is null);

    writeln("*** test: checkPassword");
    assert(checkPassword(hash, input));
    writeln("*** > passed");

    writeln("*** test: checkPassword (mismatch)");
    assert(!checkPassword(hash, "not-test"));
    writeln("*** > passed");
}


private:

import std.c.stdio;

alias ubyte uint8_t;
alias ulong uint64_t;
alias uint uint32_t;

extern (C):

/**
 * libscrypt_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen):
 * Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
 * p, buflen) and write the result into buf.  The parameters r, p, and buflen
 * must satisfy r * p < 2^30 and buflen <= (2^32 - 1) * 32.  The parameter N
 * must be a power of 2 greater than 1.
 *
 * Return 0 on success; or -1 on error.
 */
int libscrypt_scrypt(const uint8_t *, size_t, const uint8_t *, size_t, uint64_t,
    uint32_t, uint32_t, uint8_t *, size_t);

