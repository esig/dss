package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.ProfileParameters;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * This class is used to accelerate signature creation process for PAdES.
 *
 */
public class PAdESProfileParameters extends ProfileParameters {

    private static final long serialVersionUID = 852030281057208148L;

    /**
     * Cached digest value of the covered ByteRange
     */
    private byte[] digest;

    /**
     * Represents a ToBeSigned document, used for digest computation,
     * preserving a /Contents space for CMS Signed Data inclusion
     */
    private DSSDocument toBeSignedDocument;

    /**
     * Gets digest of the ByteRange
     *
     * @return byte array representing digest value
     */
    public byte[] getDigest() {
        return digest;
    }

    /**
     * Sets digest of the ByteRange
     *
     * @param digest byte array
     */
    public void setDigest(byte[] digest) {
        this.digest = digest;
    }

    /**
     * Gets ToBeSigned document
     *
     * @return {@link DSSDocument}
     */
    public DSSDocument getToBeSignedDocument() {
        return toBeSignedDocument;
    }

    /**
     * Sets ToBeSigned document
     *
     * @param toBeSignedDocument {@link DSSDocument}
     */
    public void setToBeSignedDocument(DSSDocument toBeSignedDocument) {
        this.toBeSignedDocument = toBeSignedDocument;
    }

}
