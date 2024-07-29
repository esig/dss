package eu.europa.esig.dss.model.x509.extension;

import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;

/**
 * RFC 9608 "No Revocation Available for X.509 Public Key Certificates"
 * The noRevAvail extension, defined in [X.509-2019-TC2], allows a CA to
 * indicate that no revocation information will be made available for
 * this certificate.
 * <p>
 * This extension MUST NOT be present in CA public key certificates.
 * <p>
 * Conforming CAs MUST include this extension in certificates for which
 * no revocation information will be published.  When present,
 * conforming CAs MUST mark this extension as non-critical.
 *
 */
public class NoRevAvail extends CertificateExtension {

    /** Defines the value of noRevAvail extension */
    private boolean noRevAvail;

    /**
     * Default constructor
     */
    public NoRevAvail() {
        super(CertificateExtensionEnum.NO_REVOCATION_AVAILABLE.getOid());
    }

    /**
     * Returns the noRevAvail extension value
     *
     * @return TRUE if noRevAvail extension is present, FALSE otherwise
     */
    public boolean isNoRevAvail() {
        return noRevAvail;
    }

    /**
     * Sets the noRevAvail extension value
     *
     * @param noRevAvail whether noRevAvail extension is present
     */
    public void setNoRevAvail(boolean noRevAvail) {
        this.noRevAvail = noRevAvail;
    }

}
