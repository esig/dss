package eu.europa.esig.dss.evidencerecord.common.validation;

import java.io.Serializable;
import java.util.Comparator;

/**
 * Used to compare two byte arrays.
 * Inspired by {@link <a href="https://github.com/bcgit/bc-java/blob/main/pkix/src/main/java/org/bouncycastle/tsp/ers/ByteArrayComparator.java">BC ByteArrayComparator implementation</a>}
 */
public class ByteArrayComparator implements Comparator<byte[]>, Serializable {

    private static final long serialVersionUID = 100676696837205640L;

    /** Singleton instance */
    private static ByteArrayComparator instance;

    /**
     * Default constructor
     */
    private ByteArrayComparator() {
        // empty
    }

    /**
     * Returns singleton instance of {@code ByteArrayComparator}
     *
     * @return {@link ByteArrayComparator}
     */
    public static ByteArrayComparator getInstance() {
        if (instance == null) {
            instance = new ByteArrayComparator();
        }
        return instance;
    }

    @Override
    public int compare(byte[] o1, byte[] o2) {
        for (int i = 0; i < o1.length && i < o2.length; i++) {
            int a = (o1[i] & 0xff);
            int b = (o2[i] & 0xff);
            if (a < b) {
                return -1;
            } else if (a > b) {
                return 1;
            }
        }
        return o1.length - o2.length;
    }

}
