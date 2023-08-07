package eu.europa.esig.dss.pki.model;

import eu.europa.esig.dss.pki.RevocationReason;

import java.util.Date;

public class Revocation {

    private Date revocationDate;
    private RevocationReason revocationReason;


    public Revocation(Date revocationDate, RevocationReason revocationReason ) {
        this.revocationDate = revocationDate;
        this.revocationReason = revocationReason;

    }

    public Date getRevocationDate() {
        return revocationDate;
    }


    public RevocationReason getRevocationReason() {
        return revocationReason;
    }


}
