module scrypt;

import std.string : indexOf;
import std.exception : enforce;
import std.digest.digest : toHexString;
import std.uuid : randomUUID;
import std.algorithm : splitter;
import std.array: array;
import std.conv: to;


public class SodiumChloride {
    import std.uuid;

    public string na;
    public ubyte[] cl;

    this() {
        UUID uuid = randomUUID();

        this.na = uuid.toString();
        this.cl = cast(ubyte[])this.na;
    }

    this(string str) {
        this.na = str.idup;
        this.cl = cast(ubyte[])this.na;
    }
}

ulong SCRYPT_N_DEFAULT = 16384;
uint SCRYPT_R_DEFAULT = 8;
uint SCRYPT_P_DEFAULT = 1;
size_t SCRYPT_OUTPUTLEN_DEFAULT = 128;

bool SCRYPT_DEBUG = false;

ubyte[] hex_to_ubyteArray(string hexnum) {
    import std.conv: parse;
    import std.array: array;
    import std.range: chunks;
    import std.algorithm: map;

    ubyte[] bytes = hexnum.chunks(2)
                .map!(twoDigits => twoDigits.parse!ubyte(16)).array();

    return bytes;
}

string to_hex(ubyte[] bytes) {
    import std.digest.digest;

    return bytes.toHexString();
}

ubyte[] generatePassword(string password) {
    return generatePassword(password, randomUUID.data);
}

ubyte[] generatePassword(string password, ubyte[] salt) {
    ubyte[] outpw = new ubyte[SCRYPT_OUTPUTLEN_DEFAULT];
    libscrypt_scrypt(cast(ubyte*)password.ptr, password.length, cast(ubyte*)salt.ptr, salt.length, SCRYPT_N_DEFAULT, SCRYPT_R_DEFAULT, SCRYPT_P_DEFAULT, outpw.ptr, outpw.length);

    return outpw ~ salt;
}

ubyte[] crypto_scrypt(string password, ubyte[] salt, ulong N, uint r, uint p, ulong L) {
    ubyte[] outpw = new ubyte[L];
    libscrypt_scrypt(cast(ubyte*)password.ptr,
					 password.length,
					 cast(ubyte*)salt.ptr,
					 salt.length,
					 N,
					 r,
					 p,
					 outpw.ptr,
					 outpw.length);

    return outpw ~ salt;
}

bool checkPassword(ubyte[] hash, string password) {
	import std.conv;
	import std.stdio;

	bool ret = false;

	if (SCRYPT_OUTPUTLEN_DEFAULT > hash.length) return ret;

    auto salt = hash[SCRYPT_OUTPUTLEN_DEFAULT..$];
	if(SCRYPT_DEBUG) writeln("---- > found salt : " ~ to!string(salt));
	auto checkHash = generatePassword(password, salt);
	if(SCRYPT_DEBUG) writeln("---- > hash : " ~ to!string(hash));
	if(SCRYPT_DEBUG) writeln("---- > chkh : " ~ to!string(checkHash));
	if (checkHash == hash) ret = true;
	if(SCRYPT_DEBUG) writeln("---- > returning : " ~ to!string(ret));
    return ret;
}

bool checkPassword(ubyte[] hash, string password, ulong N, uint r, uint p, ulong L) {
	import std.conv;
	import std.stdio;

	bool ret = false;

	if (L > hash.length) return ret;

    auto salt = hash[L..$];
	if(SCRYPT_DEBUG) writeln("---- > found salt : " ~ to!string(salt) ~ "(" ~ cast(string)salt ~ ")");
	auto checkHash = crypto_scrypt(password, salt,N,r,p,L);
	if(SCRYPT_DEBUG) writeln("---- > hash : " ~ to!string(hash));
	if(SCRYPT_DEBUG) writeln("---- > chkh : " ~ to!string(checkHash));
	if (checkHash == hash) ret = true;
	if(SCRYPT_DEBUG) writeln("---- > returning : " ~ to!string(ret));
    return ret;
}

unittest {
    import std.stdio;

	SCRYPT_DEBUG = true;

    //
	// unit test #1
	//
    writeln("+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=");
    writeln("+ test #1: generatePassword");
    writeln("+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=");
    auto input = "test";
    auto hash = generatePassword(input);
    writeln("*** > input: " ~ input);
    writeln("*** > scrypt: " ~ to!string(hash));
    writeln("*** > scrypt Hex: " ~ hash.toHexString());
    assert(hash !is null);

    writeln("*** test: checkPassword");
    assert(checkPassword(hash, input));
    writeln("*** > passed");

    writeln("*** test: checkPassword (mismatch)");
    assert(!checkPassword(hash, "not-test"));
    writeln("*** > passed");

    //
    //unit test #2
    //
    writeln("\n\n+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=");
    writeln("+ test #2: convert to hex string and back!");
    writeln("+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=");

    string hex = scrypt.to_hex(hash);
    ubyte[] back_to_hash = scrypt.hex_to_ubyteArray(hex);

    writeln("*** > orignal hash: " ~ to!string(hash));
    writeln("*** > to_hex: " ~ hex);
    writeln("*** > back to hash: " ~ to!string(back_to_hash));
    assert(hash == back_to_hash);
    writeln("*** > passed");

	//
	// unit test #3
	//
    writeln("\n\n+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=");
    writeln("+ test #3: crypto_scrypt with static salt");
    writeln("+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=");
	SodiumChloride salt = new SodiumChloride("test");
    auto password = "password";
    auto L = SCRYPT_OUTPUTLEN_DEFAULT;
    auto N = SCRYPT_N_DEFAULT;
    auto r = SCRYPT_R_DEFAULT;
    auto p = SCRYPT_P_DEFAULT;
    auto hash2 = crypto_scrypt(password, salt.cl, N, r, p, L);

    writeln("*** > salt: " ~ salt.na);
    writeln("*** > password: " ~ input);
    writeln("*** > L: " ~ to!string(L));
    writeln("*** > N: " ~ to!string(N));
    writeln("*** > R: " ~ to!string(r));
    writeln("*** > P: " ~ to!string(p));
    writeln("*** > scrypt: " ~ to!string(hash2));
    writeln("*** > scrypt Hex: " ~ scrypt.to_hex(hash2));
    assert(hash2 !is null);


    writeln("*** test: checkPassword");
    assert(checkPassword(hash2, password,N,r,p,L));
    writeln("*** > passed");

    writeln("*** test: checkPassword (mismatch)");
    assert(!checkPassword(hash2, "aBogusPassword",N,r,p,L));
    writeln("*** > passed");

	//
	// unit test #4
	//
    writeln("\n\n+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=");
    writeln("+ test #4: crypto_scrypt with random salt and Length=512");
    writeln("+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=");
	salt = new SodiumChloride();
    password = "password";
    L = 512;
    N = SCRYPT_N_DEFAULT;
    r = SCRYPT_R_DEFAULT;
    p = SCRYPT_P_DEFAULT;
    hash2 = crypto_scrypt(password, salt.cl, N, r, p, L);

    writeln("*** > salt: " ~ salt.na);
    writeln("*** > password: " ~ input);
    writeln("*** > L: " ~ to!string(L));
    writeln("*** > N: " ~ to!string(N));
    writeln("*** > R: " ~ to!string(r));
    writeln("*** > P: " ~ to!string(p));
    writeln("*** > scrypt: " ~ to!string(hash2));
    writeln("*** > scrypt Hex: " ~ to_hex(hash2));
    assert(hash2 !is null);

    writeln("*** test: checkPassword");
    assert(checkPassword(hash2, password,N,r,p,L));
    writeln("*** > passed");

    writeln("*** test: checkPassword (mismatch)");
    assert(!checkPassword(hash2, "aBogusPassword",N,r,p,L));
    writeln("*** > passed");
}


private:

//import std.c.stdio;
import core.stdc.stdio;

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

