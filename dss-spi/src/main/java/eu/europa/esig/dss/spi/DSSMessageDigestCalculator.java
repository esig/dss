package eu.europa.esig.dss.spi;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DSSMessageDigest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This class is used to compute {@code DSSMessageDigest} based on the provided input
 *
 */
public class DSSMessageDigestCalculator {

    /** The DigestAlgorithm used to compute message-digest */
    private final DigestAlgorithm digestAlgorithm;

    /** The java message-digest implementation used in calculations */
    private final MessageDigest messageDigest;

    /**
     * Default constructor
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to be used for message-digest computation
     */
    public DSSMessageDigestCalculator(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
        this.messageDigest = toMessageDigest(digestAlgorithm);
    }

    private MessageDigest toMessageDigest(DigestAlgorithm digestAlgorithm) {
        try {
            return digestAlgorithm.getMessageDigest();
        } catch (NoSuchAlgorithmException e) {
            throw new DSSException(String.format("Unable to build MessageDigest for the algorithm '%s' : %s",
                    digestAlgorithm.getName(), e.getMessage()), e);
        }
    }

    /**
     * Updates the digest using the provided byte
     *
     * @param byteToAdd byte to be added for digest computation
     */
    public void update(byte byteToAdd) {
        messageDigest.update(byteToAdd);
    }

    /**
     * Updates the digest using the provided array of bytes
     *
     * @param bytes array of bytes
     */
    public void update(byte[] bytes) {
        if (bytes != null) {
            messageDigest.update(bytes);
        }
    }

    /**
     * Returns the {@code DSSMessageDigest} accordingly to the current state.
     * This method resets the state of message-digest.
     *
     * @return {@link DSSMessageDigest}
     */
    public DSSMessageDigest getMessageDigest() {
        return new DSSMessageDigest(digestAlgorithm, messageDigest.digest());
    }

}
