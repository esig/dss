package eu.europa.esig.dss.model.x509.extension;

import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;

/**
 * ETSI EN 319 412-1: "5.2.2 Validity Assured - Short Term"
 * This extension indicates that the validity of the certificate is assured because the certificate is a "short-term
 * certificate". That is, the time as indicated in the certificate attribute from notBefore through notAfter, inclusive,
 * is shorter than the maximum time to process a revocation request as specified by the certificate practice statement
 * or certificate policy.
 */
public class ValidityAssuredShortTerm extends CertificateExtension {

    /** Defines the value of ext-etsi-valassured-ST-certs extension */
    private boolean valAssuredSTCerts;

    /**
     * Default constructor
     */
    public ValidityAssuredShortTerm() {
        super(CertificateExtensionEnum.VALIDITY_ASSURED_SHORT_TERM.getOid());
    }

    /**
     * Returns the ext-etsi-valassured-ST-certs extension value
     *
     * @return TRUE if ext-etsi-valassured-ST-certs extension is present, FALSE otherwise
     */
    public boolean isValAssuredSTCerts() {
        return valAssuredSTCerts;
    }

    /**
     * Sets the ext-etsi-valassured-ST-certs extension value
     *
     * @param valAssuredSTCerts whether ext-etsi-valassured-ST-certs extension is present
     */
    public void setValAssuredSTCerts(boolean valAssuredSTCerts) {
        this.valAssuredSTCerts = valAssuredSTCerts;
    }

}
