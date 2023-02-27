package eu.europa.esig.dss.model.x509.extension;

import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;

/**
 * 4.2.1.14.  Inhibit anyPolicy
 *    The inhibit anyPolicy extension can be used in certificates issued to
 *    CAs.  The inhibit anyPolicy extension indicates that the special
 *    anyPolicy OID, with the value { 2 5 29 32 0 }, is not considered an
 *    explicit match for other certificate policies except when it appears
 *    in an intermediate self-issued CA certificate.
 */
public class InhibitAnyPolicy extends CertificateExtension {

    /**
     * Indicates the number of additional non-self-issued certificates that may appear
     * in the path before anyPolicy is no longer permitted.
     */
    private int value = -1;

    /**
     * Default constructor
     */
    public InhibitAnyPolicy() {
        super(CertificateExtensionEnum.INHIBIT_ANY_POLICY.getOid());
    }

    /**
     * Gets the InhibitAnyPolicy constraint value
     *
     * @return requireExplicitPolicy int value if present, -1 otherwise
     */
    public int getValue() {
        return value;
    }

    /**
     * Sets the InhibitAnyPolicy constraint value
     *
     * @param value int InhibitAnyPolicy value
     */
    public void setValue(int value) {
        this.value = value;
    }

}
