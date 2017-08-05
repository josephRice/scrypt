module random;

import std.exception;

public class ScryptRNGException : Exception
{
    this(string message) {super(message);}
}

ubyte[] scryptRNG(uint len) {
	if (len == 0) {
		throw new ScryptRNGException
            ("RNG requested length must be greater than zero!");
	}

	ubyte[] ret = new ubyte[len];

	version(Posix)
	{
        import std.stdio;
		import std.exception;
		import std.format;

		try {
			File dev_random = File("/dev/urandom", "rb");
			dev_random.setvbuf(null, _IONBF);

			try {
				ret = dev_random.rawRead(ret);
			} catch(ErrnoException errno) {
				throw new ScryptRNGException(
                    format( "Could not read from /dev/urandom. "~
                            "ERRNO: %d, Message: %s", errno.errno, errno.msg));
			} catch(Exception ex) {
				throw new ScryptRNGException(
                    format( "Could not read from /dev/urandom. "~
                            "Message: %s",ex.msg));
			} finally {
                dev_random.close();
            }
		}
		catch(ErrnoException errno) {
			throw new ScryptRNGException(
                format( "Could not open /dev/urandom. "~
                        "ERRNO: %d, Message: %s", errno.errno, errno.msg));
		} catch(Exception ex) {
			throw new ScryptRNGException(
                format( "Could not open /dev/urandom. "~ 
                         "Message: %s", ex.msg));
		}
	} else {
		static assert(0, "OS is not supported by scrypt.");
	}

	return ret;
}

unittest {
    import std.stdio;
    import std.conv;

    writeln("+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=");
    writeln("+ Test scryptRNG(32)");
    writeln("+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=");
    ubyte[] rn1 = scryptRNG(32);
    ubyte[] rn2 = scryptRNG(32);
    writeln("*** > rn1: " ~ to!string(rn1));
    writeln("*** > rn2: " ~ to!string(rn2));


    assert((rn1 != rn2) is true);
    writeln("*** > passed");
}