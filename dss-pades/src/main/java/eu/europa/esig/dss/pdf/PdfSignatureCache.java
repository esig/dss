package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.model.DSSDocument;

import java.io.Serializable;

/**
 * This class is used as a DTO containing cached data to be used to accelerate the signature creation process
 *
 */
public class PdfSignatureCache implements Serializable {

    private static final long serialVersionUID = 8200423861085879279L;

    /**
     * Cached digest value of the covered ByteRange
     */
    private byte[] digest;

    /**
     * Represents a pre-generated PDF document, used for digest computation,
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
