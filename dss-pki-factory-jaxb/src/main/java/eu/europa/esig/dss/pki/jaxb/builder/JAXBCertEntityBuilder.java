package eu.europa.esig.dss.pki.jaxb.builder;

import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntity;
import eu.europa.esig.dss.spi.DSSASN1Utils;

import java.security.PrivateKey;
import java.util.Date;
import java.util.Objects;

/**
 * Builds a {@code JAXBCertEntity} object
 *
 */
public class JAXBCertEntityBuilder {
    
    /** CertEntity */
    private JAXBCertEntity certEntity;

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
     * Default constructor to create a new {@code JAXBCertEntity}
     */
    public JAXBCertEntityBuilder() {
        // empty
    }

    /**
     * Instantiates the builder with a pre-created {@code JAXBCertEntity} instance, to be filled with data.
     */
    public JAXBCertEntityBuilder(JAXBCertEntity certEntity) {
        this.certEntity = certEntity;
    }

    /**
     * Gets the JAXBCertEntity
     * 
     * @return {@link JAXBCertEntity}
     */
    protected JAXBCertEntity getCertEntity() {
        if (certEntity == null) {
            return new JAXBCertEntity();
        }
        return certEntity;
    }

    /**
     * Sets the certificate token associated with this entity
     *
     * @param certificateToken {@link CertificateToken}
     * @return {@link JAXBCertEntityBuilder} this
     */
    public JAXBCertEntityBuilder setCertificateToken(CertificateToken certificateToken) {
        this.certificateToken = certificateToken;
        return this;
    }

    /**
     * Sets the private key's binaries
     *
     * @param privateKey byte array
     * @return {@link JAXBCertEntityBuilder} this
     */
    public JAXBCertEntityBuilder setPrivateKey(byte[] privateKey) {
        this.privateKey = privateKey;
        return this;
    }

    /**
     * Sets the private key
     *
     * @param privateKey {@link PrivateKey}
     * @return {@link JAXBCertEntityBuilder} this
     */
    public JAXBCertEntityBuilder setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey.getEncoded();
        return this;
    }

    /**
     * Sets the revocation time of the certificate, when applicable
     *
     * @param revocationDate {@link Date}
     * @return {@link JAXBCertEntityBuilder} this
     */
    public JAXBCertEntityBuilder setRevocationDate(Date revocationDate) {
        this.revocationDate = revocationDate;
        return this;
    }

    /**
     * Sts the revocation reason of the certificate, when applicable
     *
     * @param revocationReason {@link RevocationReason}
     * @return {@link JAXBCertEntityBuilder} this
     */
    public JAXBCertEntityBuilder setRevocationReason(RevocationReason revocationReason) {
        this.revocationReason = revocationReason;
        return this;
    }

    /**
     * Sets the certificate's issuer
     *
     * @param issuer {@link JAXBCertEntity}
     * @return {@link JAXBCertEntityBuilder} this
     */
    public JAXBCertEntityBuilder setIssuer(JAXBCertEntity issuer) {
        this.issuer = issuer;
        return this;
    }

    /**
     * Sets the delegated OCSP responder for the current CA certificate
     *
     * @param ocspResponder {@link JAXBCertEntity}
     * @return {@link JAXBCertEntityBuilder} this
     */
    public JAXBCertEntityBuilder setOcspResponder(JAXBCertEntity ocspResponder) {
        this.ocspResponder = ocspResponder;
        return this;
    }

    /**
     * Sets if the certificate is trusted
     *
     * @param trustAnchor if the certificate is trusted
     * @return {@link JAXBCertEntityBuilder} this
     */
    public JAXBCertEntityBuilder setTrustAnchor(boolean trustAnchor) {
        this.trustAnchor = trustAnchor;
        return this;
    }

    /**
     * Sets the corresponding PKI's name
     *
     * @param pkiName {@link String}
     * @return {@link JAXBCertEntityBuilder} this
     */
    public JAXBCertEntityBuilder setPkiName(String pkiName) {
        this.pkiName = pkiName;
        return this;
    }

    /**
     * Builds the {@code JAXBCertEntity} object
     * 
     * @return {@link JAXBCertEntity}
     */
    public JAXBCertEntity build() {
        final JAXBCertEntity certEntity = getCertEntity();

        final CertificateToken certificateToken;
        if (certEntity.getCertificateToken() == null) {
            Objects.requireNonNull(this.certificateToken, "CertificateToken shall be provided!");
            certificateToken = this.certificateToken;
            certEntity.setCertificateToken(this.certificateToken);
        } else {
            certificateToken = certEntity.getCertificateToken();
        }

        if (certEntity.getSubject() == null) {
            certEntity.setSubject(DSSASN1Utils.getSubjectCommonName(certificateToken));
        }
        if (certEntity.getSerialNumber() == null) {
            certEntity.setSerialNumber(certificateToken.getSerialNumber().longValue());
        }
        if (certEntity.getPrivateKeyBinaries() == null) {
            Objects.requireNonNull(privateKey, "PrivateKey shall be provided!");
            certEntity.setPrivateKey(privateKey);
        }
        if (certEntity.getIssuer() == null) {
            certEntity.setIssuer(issuer);
        }
        if (certEntity.getRevocationDate() == null) {
            certEntity.setRevocationDate(revocationDate);
        }
        if (certEntity.getRevocationReason() == null) {
            certEntity.setRevocationReason(revocationReason);
        }
        if (certEntity.getOcspResponder() == null) {
            certEntity.setOcspResponder(ocspResponder);
        }
        if (!certEntity.isTrustAnchor()) {
            certEntity.setTrustAnchor(trustAnchor);
        }
        if (certEntity.getPkiName() == null) {
            certEntity.setPkiName(pkiName);
        }

        return certEntity;
    }

}
