package eu.europa.esig.dss.pki.model;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.pki.manifest.RevocationReason;
import eu.europa.esig.dss.pki.exception.Error500Exception;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;


public class DBCertEntity implements CertEntity {
    private static final Logger LOG = LoggerFactory.getLogger(DBCertEntity.class);
    private String internalId = UUID.randomUUID().toString();

    private String subject;

    private Long serialNumber;

    private CertificateToken certificateToken;

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

    public void setCertificateToken(CertificateToken certificateToken) {

        this.certificateToken = certificateToken;
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


    @Override
    public PrivateKey getPrivateKeyObject() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(this.getPrivateKeyAlgo());
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(this.getPrivateKey());
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (GeneralSecurityException e) {

            throw new Error500Exception("Unable to regenerate the private key");
        }
    }


    @Override
    public CertificateToken getCertificateToken() {
        return certificateToken;
    }

    @Override
    public EncryptionAlgorithm getEncryptionAlgorithm() {
        return EncryptionAlgorithm.forKey(this.getPrivateKeyObject());
    }

    public List<CertificateToken> getCertificateChain() {
        List<CertificateToken> certChain = new ArrayList<>();
        DBCertEntity entity = this;
        while (entity != null) {
            DBCertEntity parent = entity.getParent();
            certChain.add(entity.getCertificateToken());
            if (entity.getInternalId().equals(parent.getInternalId())) {
                break;
            }
            entity = parent;
        }
        return certChain;
    }


}
