package eu.europa.esig.dss.pki.model;

import eu.europa.esig.dss.pki.RevocationReason;
import java.util.Date;
import java.util.UUID;


public class DBCertEntity {

    private String internalId= UUID.randomUUID().toString();

    private String subject;

    private Long serialNumber;

    private byte[] certificate;

    private byte[] privateKey;

    private String privateKeyAlgo;

    private String digestAlgo;

    private Date revocationDate;

    private RevocationReason revocationReason;

    private boolean suspended;

    private DBCertEntity parent;

    private DBCertEntity ocspResponder;

    private boolean pss;

    private boolean trustAnchor;

    private boolean ca;

    private boolean ocsp;

    private boolean tsa;

    private boolean toBeIgnored;

    private String pkiName;

    public String getInternalId() {
        return internalId;
    }

    public void setInternalId(String internalId) {
        this.internalId = internalId;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public Long getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(Long serialNumber) {
        this.serialNumber = serialNumber;
    }

    public byte[] getCertificate() {
        return certificate;
    }

    public void setCertificate(byte[] certificate) {
        this.certificate = certificate;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(byte[] privateKey) {
        this.privateKey = privateKey;
    }

    public String getPrivateKeyAlgo() {
        return privateKeyAlgo;
    }

    public void setPrivateKeyAlgo(String privateKeyAlgo) {
        this.privateKeyAlgo = privateKeyAlgo;
    }

    public String getDigestAlgo() {
        return digestAlgo;
    }

    public void setDigestAlgo(String digestAlgo) {
        this.digestAlgo = digestAlgo;
    }

    public Date getRevocationDate() {
        return revocationDate;
    }

    public void setRevocationDate(Date revocationDate) {
        this.revocationDate = revocationDate;
    }

    public RevocationReason getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(RevocationReason revocationReason) {
        this.revocationReason = revocationReason;
    }

    public boolean isSuspended() {
        return suspended;
    }

    public void setSuspended(boolean suspended) {
        this.suspended = suspended;
    }

    public DBCertEntity getParent() {
        return parent;
    }

    public void setParent(DBCertEntity parent) {
        this.parent = parent;
    }

    public DBCertEntity getOcspResponder() {
        return ocspResponder;
    }

    public void setOcspResponder(DBCertEntity ocspResponder) {
        this.ocspResponder = ocspResponder;
    }

    public boolean isPss() {
        return pss;
    }

    public void setPss(boolean pss) {
        this.pss = pss;
    }

    public boolean isTrustAnchor() {
        return trustAnchor;
    }

    public void setTrustAnchor(boolean trustAnchor) {
        this.trustAnchor = trustAnchor;
    }

    public boolean isCa() {
        return ca;
    }

    public void setCa(boolean ca) {
        this.ca = ca;
    }

    public boolean isOcsp() {
        return ocsp;
    }

    public void setOcsp(boolean ocsp) {
        this.ocsp = ocsp;
    }

    public boolean isTsa() {
        return tsa;
    }

    public void setTsa(boolean tsa) {
        this.tsa = tsa;
    }

    public boolean isToBeIgnored() {
        return toBeIgnored;
    }

    public void setToBeIgnored(boolean toBeIgnored) {
        this.toBeIgnored = toBeIgnored;
    }

    public String getPkiName() {
        return pkiName;
    }

    public void setPkiName(String pkiName) {
        this.pkiName = pkiName;
    }
//    @Override
//    public boolean equals(Object o) {
//        if (this == o) return true;
//        if (!(o instanceof DBCertEntity)) return false;
//        DBCertEntity that = (DBCertEntity) o;
//        return isSuspended() == that.isSuspended() && isPss() == that.isPss() && isTrustAnchor() == that.isTrustAnchor() && isCa() == that.isCa() && isOcsp() == that.isOcsp() && isTsa() == that.isTsa() && isToBeIgnored() == that.isToBeIgnored() && Objects.equals(getInternalId(), that.getInternalId()) && Objects.equals(getSubject(), that.getSubject()) && Objects.equals(getSerialNumber(), that.getSerialNumber()) && Arrays.equals(getCertificate(), that.getCertificate()) && Arrays.equals(getPrivateKey(), that.getPrivateKey()) && Objects.equals(getPrivateKeyAlgo(), that.getPrivateKeyAlgo()) && Objects.equals(getDigestAlgo(), that.getDigestAlgo()) && Objects.equals(getRevocationDate(), that.getRevocationDate()) && getRevocationReason() == that.getRevocationReason() && Objects.equals(getParent(), that.getParent()) && Objects.equals(getOcspResponder(), that.getOcspResponder()) && Objects.equals(getPkiName(), that.getPkiName());
//    }
//
//    @Override
//    public int hashCode() {
//        int result = Objects.hash(getInternalId(), getSubject(), getSerialNumber(), getPrivateKeyAlgo(), getDigestAlgo(), getRevocationDate(), getRevocationReason(), isSuspended(), getParent(), getOcspResponder(), isPss(), isTrustAnchor(), isCa(), isOcsp(), isTsa(), isToBeIgnored(), getPkiName());
//        result = 31 * result + Arrays.hashCode(getCertificate());
//        result = 31 * result + Arrays.hashCode(getPrivateKey());
//        return result;
//    }
}
