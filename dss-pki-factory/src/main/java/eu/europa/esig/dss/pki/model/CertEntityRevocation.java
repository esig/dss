package eu.europa.esig.dss.pki.model;


import eu.europa.esig.dss.enumerations.RevocationReason;

import java.util.Date;

/**
 * This class represents the revocation information for a certificate.
 */
public class CertEntityRevocation {

    /** The revocation time of the certificate */
    private final Date revocationDate;

    /** The revocation reason */
    private final RevocationReason revocationReason;

    /**
     * Constructs a new Revocation instance with the provided revocation date and reason.
     *
     * @param revocationDate {@link Date} the date of revocation.
     * @param revocationReason {@link Date} the reason for revocation.
     */
    public CertEntityRevocation(Date revocationDate, RevocationReason revocationReason) {
        this.revocationDate = revocationDate;
        this.revocationReason = revocationReason;
    }

    /**
     * Retrieves the date of revocation.
     *
     * @return The date of revocation.
     */
    public Date getRevocationDate() {
        return revocationDate;
    }

    /**
     * Retrieves the reason for revocation.
     *
     * @return The reason for revocation.
     */
    public RevocationReason getRevocationReason() {
        return revocationReason;
    }

}
