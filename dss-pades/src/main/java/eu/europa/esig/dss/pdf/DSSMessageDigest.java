package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;

/**
 * This class contains a digest algorithm and a digest value to be incorporated
 * within message-digest field of a CMS signed attributes.
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

    @Override
    public String toString() {
        return "MessageDigest [" + super.toString() + "]";
    }

}
