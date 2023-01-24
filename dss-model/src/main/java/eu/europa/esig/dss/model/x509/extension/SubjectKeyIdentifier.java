package eu.europa.esig.dss.model.x509.extension;

import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;

/**
 * 4.2.1.2.  Subject Key Identifier
 *    The subject key identifier extension provides a means of identifying
 *    certificates that contain a particular public key.
 */
public class SubjectKeyIdentifier extends CertificateExtension {

    /** The subject key identifier */
    private byte[] ski;

    /**
     * Default constructor
     */
    public SubjectKeyIdentifier() {
        super(CertificateExtensionEnum.SUBJECT_KEY_IDENTIFIER.getOid());
    }

    /**
     * Returns the subject key identifier
     *
     * @return byte array
     */
    public byte[] getSki() {
        return ski;
    }

    /**
     * Sets the subject key identifier
     *
     * @param ski byte array
     */
    public void setSki(byte[] ski) {
        this.ski = ski;
    }

}
