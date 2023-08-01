package eu.europa.esig.dss.pki.model;

import eu.europa.esig.dss.pki.RevocationReason;

import java.util.Date;

public class Revocation {

    private Date revocationDate;
    private RevocationReason revocationReason;
    private DBCertEntity dbCertEntity;

    public Revocation(Date revocationDate, RevocationReason revocationReason, DBCertEntity dbCertEntity) {
        this.revocationDate = revocationDate;
        this.revocationReason = revocationReason;
        this.dbCertEntity = dbCertEntity;
    }

    public Date getRevocationDate() {
        return revocationDate;
    }


    public RevocationReason getRevocationReason() {
        return revocationReason;
    }

    public DBCertEntity getDbCertEntity() {
        return dbCertEntity;
    }

    public void setDbCertEntity(DBCertEntity dbCertEntity) {
        this.dbCertEntity = dbCertEntity;
    }
}
