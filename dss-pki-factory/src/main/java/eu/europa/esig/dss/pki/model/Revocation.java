package eu.europa.esig.dss.pki.model;

import eu.europa.esig.pki.manifest.RevocationReason;

import java.util.Date;

/**
 * This class represents the revocation information for a certificate.
 */
public class Revocation {

    private Date revocationDate;
    private RevocationReason revocationReason;


    /**
     * Constructs a new Revocation instance with the provided revocation date and reason.
     *
     * @param revocationDate   The date of revocation.
     * @param revocationReason The reason for revocation.
     */
    public Revocation(Date revocationDate, RevocationReason revocationReason) {
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
