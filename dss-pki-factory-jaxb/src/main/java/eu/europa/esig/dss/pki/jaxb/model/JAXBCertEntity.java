package eu.europa.esig.dss.pki.jaxb.model;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.model.CertEntity;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Represents a JAXB implementation of a {@code CertEntity}.
 *
 */
public class JAXBCertEntity implements CertEntity {

    private static final long serialVersionUID = 5363087537311186428L;

    /** Certificate's subject name */
    private String subject;

    /** Certificate's serial number */
    private Long serialNumber;

    /** Certificate token */
    private CertificateToken certificateToken;

    /** DER-encoded private key associated with the certificate */
    private byte[] privateKey;

    /** Revocation time of the certificate, when applicable */
    private Date revocationDate;

    /** Revocation reason of the certificate, when applicable */
    private RevocationReason revocationReason;

    /** The issuer's cert entity */
    private JAXBCertEntity issuer;

    /** Delegated OCSP responder */
    private JAXBCertEntity ocspResponder;

    /** Defines whether the current certificate is a trust anchor */
    private boolean trustAnchor;

    /** The associated PKI factory's name */
    private String pkiName;

    /**
     * Default constructor
     */
    public JAXBCertEntity() {
        // empty
    }

    /**
     * Gets the certificate's common name
     *
     * @return {@link String}
     */
    public String getSubject() {
        return subject;
    }

    /**
     * Sets the certificate's common name
     *
     * @param subject {@link String}
     */
    public void setSubject(String subject) {
        this.subject = subject;
    }

    /**
     * Gets the certificate's serial number
     *
     * @return {@link Long}
     */
    public Long getSerialNumber() {
        return serialNumber;
    }

    /**
     * Sets the certificate's serial number
     *
     * @param serialNumber {@link Long}
     */
    public void setSerialNumber(Long serialNumber) {
        this.serialNumber = serialNumber;
    }

    /**
     * Retrieves the CertificateToken associated with this entity.
     *
     * @return The CertificateToken.
     */
    @Override
    public CertificateToken getCertificateToken() {
        return certificateToken;
    }

    /**
     * Sets the certificate token associated with this entity
     *
     * @param certificateToken {@link CertificateToken}
     */
    public void setCertificateToken(CertificateToken certificateToken) {
        this.certificateToken = certificateToken;
    }

    /**
     * Gets the private key binaries
     *
     * @return byte array
     */
    public byte[] getPrivateKeyBinaries() {
        return privateKey;
    }

    /**
     * Sets the private key's binaries
     *
     * @param privateKey byte array
     */
    public void setPrivateKey(byte[] privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * Gets the revocation date, when applicable
     *
     * @return {@link Date}
     */
    public Date getRevocationDate() {
        return revocationDate;
    }

    /**
     * Sets the revocation time of the certificate, when applicable
     *
     * @param revocationDate {@link Date}
     */
    public void setRevocationDate(Date revocationDate) {
        this.revocationDate = revocationDate;
    }

    /**
     * Gets the revocation reason of the certificate, when applicable
     *
     * @return {@link RevocationReason}
     */
    public RevocationReason getRevocationReason() {
        return revocationReason;
    }

    /**
     * Sts the revocation reason of the certificate, when applicable
     *
     * @param revocationReason {@link RevocationReason}
     */
    public void setRevocationReason(RevocationReason revocationReason) {
        this.revocationReason = revocationReason;
    }

    /**
     * Gets the certificate's issuer
     *
     * @return {@link JAXBCertEntity}
     */
    public JAXBCertEntity getIssuer() {
        return issuer;
    }

    /**
     * Sets the certificate's issuer
     *
     * @param issuer {@link JAXBCertEntity}
     */
    public void setIssuer(JAXBCertEntity issuer) {
        this.issuer = issuer;
    }

    /**
     * Gets the delegated OCSP responder for the current CA certificate
     *
     * @return {@link JAXBCertEntity}
     */
    public JAXBCertEntity getOcspResponder() {
        return ocspResponder;
    }

    /**
     * Sets the delegated OCSP responder for the current CA certificate
     *
     * @param ocspResponder {@link JAXBCertEntity}
     */
    public void setOcspResponder(JAXBCertEntity ocspResponder) {
        this.ocspResponder = ocspResponder;
    }

    /**
     * Gets if the certificate is trusted
     *
     * @return TRUE if the certificate is trusted, FALSE otherwise
     */
    public boolean isTrustAnchor() {
        return trustAnchor;
    }

    /**
     * Sets if the certificate is trusted
     *
     * @param trustAnchor if the certificate is trusted
     */
    public void setTrustAnchor(boolean trustAnchor) {
        this.trustAnchor = trustAnchor;
    }

    /**
     * Gets the corresponding PKI's name
     *
     * @return {@link String}
     */
    public String getPkiName() {
        return pkiName;
    }

    /**
     * Sets the corresponding PKI's name
     *
     * @param pkiName {@link String}
     */
    public void setPkiName(String pkiName) {
        this.pkiName = pkiName;
    }

    @Override
    public PrivateKey getPrivateKey() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(getCertificateToken().getPublicKey().getAlgorithm());
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(this.getPrivateKeyBinaries());
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (GeneralSecurityException e) {
            throw new DSSException("Unable to regenerate the private key");
        }
    }

    /**
     * Retrieves the EncryptionAlgorithm based on the private key.
     *
     * @return The EncryptionAlgorithm.
     */
    @Override
    public EncryptionAlgorithm getEncryptionAlgorithm() {
        return EncryptionAlgorithm.forKey(this.getPrivateKey());
    }

    /**
     * Retrieves the certificate chain as a list of CertificateToken objects.
     *
     * @return The list of CertificateToken objects in the certificate chain.
     */
    @Override
    public List<CertificateToken> getCertificateChain() {
        List<CertificateToken> certChain = new ArrayList<>();
        JAXBCertEntity entity = this;
        while (entity != null) {
            JAXBCertEntity parent = entity.getIssuer();
            certChain.add(entity.getCertificateToken());
            if (entity.getCertificateToken().equals(parent.getCertificateToken())) {
                break;
            }
            entity = parent;
        }
        return certChain;
    }


}
