package pt.ulisboa.tecnico.sec.g19.hdscoin.server.util;

import java.security.SecureRandom;
import java.util.Objects;
import java.util.Random;

// Based on https://stackoverflow.com/a/41156
public class RandomString {

    /**
     * Generate a random string.
     */
    public String nextString() {
        for (int idx = 0; idx < buf.length; ++idx)
            buf[idx] = symbols[random.nextInt(symbols.length)];
        return new String(buf);
    }

    private final Random random;

    private final char[] symbols;

    private final char[] buf;

    public RandomString(int length, Random random) {
        if (length < 1) throw new IllegalArgumentException();
        this.random = Objects.requireNonNull(random);
        this.buf = new char[length];

        this.symbols = new char[94];
        for(int i = 0; i < 94; i++) {
            this.symbols[i] = (char)(33 + i);
        }
    }

    /**
     * Create a random string generator from a secure random generator.
     */
    public RandomString(int length) {
        this(length, new SecureRandom());
    }

}