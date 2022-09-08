package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

/**
 * This class contains a digest algorithm and a digest value for message-digest computation.
 *
 */
public class DSSMessageDigest extends Digest {

    private static final long serialVersionUID = 8294786241127932403L;

    /**
     * Empty constructor to instantiate message-digest
     */
    public DSSMessageDigest() {
        super();
    }

    /**
     * Default constructor with provided digest algorithm and the corresponding hash value
     *
     * @param algorithm {@link DigestAlgorithm} used algorithm
     * @param value byte array digest
     */
    public DSSMessageDigest(DigestAlgorithm algorithm, byte[] value) {
        super(algorithm, value);
    }

    /**
     * Constructor with provided {@code Digest} object
     *
     * @param digest {@link Digest}
     */
    public DSSMessageDigest(Digest digest) {
        this(digest.getAlgorithm(), digest.getValue());
    }

    /**
     * Creates empty message-digest object
     *
     * @return {@link DSSMessageDigest} with empty values
     */
    public static DSSMessageDigest createEmptyDigest() {
        return new DSSMessageDigest();
    }

    /**
     * Checks whether the object contains a value
     *
     * @return TRUE if the object is empty, FALSE otherwise
     */
    public boolean isEmpty() {
        return getAlgorithm() == null || getValue() == null;
    }

    @Override
    public String toString() {
        return "MessageDigest [" + super.toString() + "]";
    }

}
