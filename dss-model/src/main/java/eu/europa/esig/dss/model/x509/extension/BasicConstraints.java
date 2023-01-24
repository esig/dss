package eu.europa.esig.dss.model.x509.extension;

import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;

/**
 * 4.2.1.9.  Basic Constraints
 *    The basic constraints extension identifies whether the subject of the
 *    certificate is a CA and the maximum depth of valid certification
 *    paths that include this certificate.
 */
public class BasicConstraints extends CertificateExtension {

    /**
     * Defines whether the certificate is a CA certificate
     */
    private boolean ca;

    /**
     * Gives the maximum number of non-self-issued intermediate certificates that
     * may follow this certificate in a valid certification path
     */
    private int pathLenConstraint;

    /**
     * Default constructor
     */
    public BasicConstraints() {
        super(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
    }

    /**
     * Returns whether the certificate is a CA certificate
     *
     * @return TRUE if the certificate is a CA certificate, FALSE otherwise
     */
    public boolean isCa() {
        return ca;
    }

    /**
     * Sets whether the certificate is a CA certificate
     *
     * @param ca TRUE if the certificate is a CA certificate, FALSE otherwise
     */
    public void setCa(boolean ca) {
        this.ca = ca;
    }

    /**
     * Returns the pathLenConstraint value
     *
     * @return the pathLenConstraint value
     */
    public int getPathLenConstraint() {
        return pathLenConstraint;
    }

    /**
     * Sets the pathLenConstraint value
     *
     * @param pathLenConstraint the pathLenConstraint value
     */
    public void setPathLenConstraint(int pathLenConstraint) {
        this.pathLenConstraint = pathLenConstraint;
    }

}
