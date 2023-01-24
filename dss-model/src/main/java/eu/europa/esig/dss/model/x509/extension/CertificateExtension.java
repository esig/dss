package eu.europa.esig.dss.model.x509.extension;

import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.OidDescription;
import eu.europa.esig.dss.model.x509.CertificateToken;

/**
 * Abstract implementation of a certificate extension
 *
 */
public class CertificateExtension implements OidDescription {

    /** The corresponding OID of the certificate extension */
    private final String oid;

    /** The user-friendly label (optional) */
    private String description;

    /** Defines whether the certificate extension is critical or not */
    private boolean critical;

    /**
     * Constructor with a certificate extension OID
     *
     * @param oid {@link String} certificate extension OID
     */
    public CertificateExtension(final String oid) {
        this.oid = oid;
    }

    /**
     * Constructor from a {@code CertificateExtensionEnum}
     *
     * @param certificateExtensionEnum {@link CertificateExtensionEnum}
     */
    public CertificateExtension(CertificateExtensionEnum certificateExtensionEnum) {
        this.oid = certificateExtensionEnum.getOid();
        this.description = certificateExtensionEnum.getDescription();
    }

    @Override
    public String getOid() {
        return oid;
    }

    @Override
    public String getDescription() {
        return description;
    }

    /**
     * Returns whether the certificate extension is critical or not
     *
     * @return TRUE if the certificate extension is critical, FALSE otherwise
     */
    public boolean isCritical() {
        return critical;
    }

    /**
     * Checks and sets whether the certificate extension is critical
     *
     * @param certificateToken {@link CertificateToken} to check
     */
    public void checkCritical(CertificateToken certificateToken) {
        this.critical = certificateToken.getCertificate().getCriticalExtensionOIDs().contains(oid);
    }

}
