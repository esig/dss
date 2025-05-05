package eu.europa.esig.dss.model.policy;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;

import java.io.Serializable;
import java.util.Objects;

/**
 * DTO containing a pair of an {@code eu.europa.esig.dss.enumerations.EncryptionAlgorithm} and
 * its corresponding minimal allowed key size
 *
 */
public class EncryptionAlgorithmWithMinKeySize implements Serializable {

    private static final long serialVersionUID = -311662580001422950L;

    /** The Encryption algorithm */
    private final EncryptionAlgorithm encryptionAlgorithm;

    /** The minimal accepted key size */
    private final int minKeySize;

    /**
     * Default constructor
     *
     * @param encryptionAlgorithm {@link EncryptionAlgorithm}
     * @param minKeySize integer key size. 0 when not defined
     */
    public EncryptionAlgorithmWithMinKeySize(final EncryptionAlgorithm encryptionAlgorithm, int minKeySize) {
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.minKeySize = minKeySize;
    }

    /**
     * Gets Encryption algorithm
     *
     * @return {@link EncryptionAlgorithm}
     */
    public EncryptionAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    /**
     * Gets the minimum key size value
     *
     * @return key size
     */
    public int getMinKeySize() {
        return minKeySize;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        EncryptionAlgorithmWithMinKeySize that = (EncryptionAlgorithmWithMinKeySize) o;
        return minKeySize == that.minKeySize
                && encryptionAlgorithm == that.encryptionAlgorithm;
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(encryptionAlgorithm);
        result = 31 * result + minKeySize;
        return result;
    }

    @Override
    public String toString() {
        return "EncryptionAlgorithmWithMinKeySize [" +
                "encryptionAlgorithm=" + encryptionAlgorithm +
                ", minKeySize=" + minKeySize +
                ']';
    }

}
