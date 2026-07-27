/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pki.x509.revocation.crl;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.exception.PKIException;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.CertEntityRepository;
import eu.europa.esig.dss.pki.model.CertEntityRevocation;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * An implementation of the CRLSource interface that provides methods to obtain Certificate Revocation Lists (CRLs)
 * for certificate revocation checks. The CRLs are retrieved based on the CertEntity (certificate entity) and
 * optionally specified production and next update dates.
 */
public class PKICRLSource implements CRLSource {

    private static final long serialVersionUID = 6912729291417315212L;

    private static final Logger LOG = LoggerFactory.getLogger(PKICRLSource.class);

    /**
     * The repository managing the PKI
     */
    private final CertEntityRepository certEntityRepository;

    /**
     * Cert Entity issuing the CRL responses
     */
    private CertEntity crlIssuer;

    /**
     * Indicates the issue date of the CRL
     */
    private Date thisUpdate;

    /**
     * Indicates the date by which a new CRL will be issued
     */
    private Date nextUpdate;

    /**
     * The DigestAlgorithm to be used on CRL signing
     */
    private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA512;

    /**
     * Encryption algorithm of the signature of the CRL
     */
    private EncryptionAlgorithm encryptionAlgorithm;

    /**
     * Creates a PKICRLSource instance with a CRL issuer being the issuer certificate token provided on the CRL request
     *
     * @param certEntityRepository {@link CertEntityRepository}
     */
    public PKICRLSource(CertEntityRepository<? extends CertEntity> certEntityRepository) {
        Objects.requireNonNull(certEntityRepository, "Certificate repository shall be provided!");
        this.certEntityRepository = certEntityRepository;
    }

    /**
     * Creates a PKICRLSource instance with enforced CRL signer {@code CertEntity}
     *
     * @param certEntityRepository {@link CertEntityRepository}
     * @param crlIssuer            {@link CertEntity} to issue CRL
     */
    public PKICRLSource(CertEntityRepository<? extends CertEntity> certEntityRepository, CertEntity crlIssuer) {
        this(certEntityRepository);
        this.crlIssuer = crlIssuer;
    }

    /**
     * Gets nextUpdate value
     *
     * @return {@link Date}
     */
    public Date getNextUpdate() {
        return nextUpdate;
    }

    /**
     * Set the next update date for the CRL generation.
     * If not set, the nextUpdate field will not be added to CRL.
     *
     * @param nextUpdate The next update date to be set.
     */
    public void setNextUpdate(Date nextUpdate) {
        this.nextUpdate = nextUpdate;
    }

    /**
     * Gets thisUpdate value.
     * If not defined, returns the current time.
     *
     * @return {@link Date}
     */
    protected Date getThisUpdate() {
        if (thisUpdate == null) {
            return new Date();
        }
        return thisUpdate;
    }

    /**
     * Set the production date for the CRL generation.
     *
     * @param thisUpdate The production date to be set.
     */
    public void setThisUpdate(Date thisUpdate) {
        this.thisUpdate = thisUpdate;
    }

    /**
     * Sets Digest Algorithm to be used on CRL request signature
     * Default: SHA512 ({@code DigestAlgorithm.SHA512})
     *
     * @param digestAlgorithm {@link DigestAlgorithm}
     */
    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    /**
     * Sets encryption algorithm to be used on CRL signature generation.
     * If not defined, the encryption algorithm from the given {@code CertEntity} CRL issuer will be used.
     * NOTE: It is important to ensure that the defined encryption algorithm is supported by the CRL issuer.
     *
     * @param encryptionAlgorithm {@link EncryptionAlgorithm}
     */
    public void setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    /**
     * Returns a {@code CertEntity} to be used as an CRL issuer.
     *
     * @param certificateToken {@link CertificateToken} to request CRL for
     * @param issuerCertificateToken {@link CertificateToken} issued the {@code certificateToken}
     * @return {@link CertEntity} representing the entry to be used as an issuer of the CRL
     */
    protected CertEntity getCrlIssuer(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
        CertEntity currentCRLIssuer;
        if (crlIssuer != null) {
            currentCRLIssuer = crlIssuer;
        } else {
            currentCRLIssuer = certEntityRepository.getByCertificateToken(issuerCertificateToken);
            if (currentCRLIssuer == null) {
                throw new PKIException(String.format("CertEntity for certificate token with Id '%s' " +
                        "not found in the repository! Provide a valid issuer or use #setCrlIssuer method to set a custom issuer.",
                        issuerCertificateToken.getDSSIdAsString()));
            }
        }
        return currentCRLIssuer;
    }

    /**
     * Sets a CertEntity to be used as a CRL issuer.
     * If not defined, the certificate issuer will be used as a CRL issuing certificate.
     *
     * @param crlIssuer {@link CertEntity}
     */
    public void setCrlIssuer(CertEntity crlIssuer) {
        this.crlIssuer = crlIssuer;
    }

    /**
     * Retrieves a Certificate Revocation List (CRL) token for the given certificate and its issuer certificate if the CertEntity is not already.
     *
     * @param certificateToken       The CertificateToken representing the certificate to be checked for revocation.
     * @param issuerCertificateToken The CertificateToken representing the issuer certificate of the certificate to be verified.
     * @return The CRLToken representing the revocation status of the certificate.
     */
    @Override
    public CRLToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken)  {
        Objects.requireNonNull(certificateToken, "Certificate cannot be null!");
        Objects.requireNonNull(issuerCertificateToken, "The issuer of the certificate to be verified cannot be null!");

        final String dssIdAsString = certificateToken.getDSSIdAsString();
        LOG.trace("--> PKICRLSource queried for {}", dssIdAsString);
        if (!canGenerate(certificateToken, issuerCertificateToken)) {
            return null;
        }

        // Obtain the CRL bytes based on the productionDate and nextUpdate parameters.
        CertEntity currentCRLIssuer = getCrlIssuer(certificateToken, issuerCertificateToken);

        try {
            CRLBinary crlBinary = generateCRL(currentCRLIssuer);

            // Build the CRLValidity using CRLUtils from the retrieved CRL bytes and the issuerCertificateToken.
            final CRLValidity crlValidity = CRLUtils.buildCRLValidity(crlBinary, issuerCertificateToken);

            // Create a new CRLToken with the certificateToken and the CRLValidity, and set its origin as external.
            final CRLToken crlToken = new CRLToken(certificateToken, crlValidity);
            crlToken.setExternalOrigin(RevocationOrigin.EXTERNAL);
            return crlToken;

        } catch (Exception e) {
            throw new PKIException(String.format("Unable to build a CRL for certificate with Id '%s'. " +
                    "Reason : %s", certificateToken.getDSSIdAsString(), e.getMessage()), e);
        }
    }

    /**
     * Returns whether the current implementation is able to produce a CRL for the given {@code certificateToken}
     *
     * @param certificateToken {@link CertificateToken} to produce a CRL for
     * @param issuerCertificateToken {@link CertificateToken} representing an issuer of the {@code certificateToken}
     * @return TRUE if the current implementation is able to produce a CRL for the given pair, FALSE otherwise
     */
    protected boolean canGenerate(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
        List<String> crlAccessUrls = CertificateExtensionsUtils.getCRLAccessUrls(certificateToken);
        if (Utils.isCollectionEmpty(crlAccessUrls)) {
            LOG.debug("No CRL location found for {}", certificateToken.getDSSIdAsString());
            return false;
        }
        return true;
    }

    /**
     * Generates a CRL token and returns encoded binaries
     *
     * @param crlIssuer {@link CertEntity} issuer of the CRL
     * @return {@link CRLBinary} representing a DER-encoded CRL token
     * @throws IOException if an exception occurs on CRL generation
     * @throws OperatorCreationException if an exception occurs on CRL signing
     */
    @SuppressWarnings("unchecked")
    protected CRLBinary generateCRL(CertEntity crlIssuer) throws IOException, OperatorCreationException {
        X509CertificateHolder caCert = DSSASN1Utils.getX509CertificateHolder(crlIssuer.getCertificateToken());

        Map<CertEntity, CertEntityRevocation> revocationList = certEntityRepository.getRevocationList(crlIssuer);

        SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm(crlIssuer);

        Date thisUpdateTime = getThisUpdate();
        X509v2CRLBuilder builder = new X509v2CRLBuilder(caCert.getSubject(), thisUpdateTime);

        Date nextUpdateTime = getNextUpdate();
        if (nextUpdateTime != null) {
            builder.setNextUpdate(nextUpdateTime);
        }

        addRevocationsToCRL(builder, revocationList);
        addCRLExtensions(builder);

        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm.getJCEId()).build(crlIssuer.getPrivateKey());

        X509CRLHolder crl = builder.build(signer);

        return new CRLBinary(crl.getEncoded());
    }

    /**
     * Returns a signature algorithm to be used on CRL creation
     *
     * @param crlIssuer {@link CertEntity} to sign the CRL
     * @return {@link SignatureAlgorithm}
     */
    protected SignatureAlgorithm getSignatureAlgorithm(CertEntity crlIssuer) {
        EncryptionAlgorithm signatureEncryptionAlgorithm = this.encryptionAlgorithm;
        if (signatureEncryptionAlgorithm != null) {
            if (!signatureEncryptionAlgorithm.isEquivalent(crlIssuer.getEncryptionAlgorithm())) {
                throw new IllegalArgumentException(String.format(
                        "Defined EncryptionAlgorithm '%s' is not equivalent to the one returned by CRL Issuer '%s'", signatureEncryptionAlgorithm, crlIssuer.getEncryptionAlgorithm()));

            }
        } else {
            signatureEncryptionAlgorithm = crlIssuer.getEncryptionAlgorithm();
        }
        return SignatureAlgorithm.getAlgorithm(signatureEncryptionAlgorithm, digestAlgorithm);
    }

    /**
     * Adds revocations to the CRL builder based on the provided CertEntity and revocationList.
     *
     * @param revocationList List of Revocation objects containing the revocation information.
     * @param builder        The X509v2CRLBuilder instance to which the entries will be added.
     */
    protected void addRevocationsToCRL(X509v2CRLBuilder builder, Map<CertEntity, CertEntityRevocation> revocationList) {
        if (Utils.isMapNotEmpty(revocationList)) {
            revocationList.forEach((key, value) -> {
                X509CertificateHolder entry = DSSASN1Utils.getX509CertificateHolder(key.getCertificateToken());
                builder.addCRLEntry(entry.getSerialNumber(), value.getRevocationDate(), value.getRevocationReason().getValue());
            });
        }
    }

    /**
     * Adds CRL extensions to be included within a generated CRL
     *
     * @param builder {@link X509v2CRLBuilder}
     */
    protected void addCRLExtensions(X509v2CRLBuilder builder) {
        // extend the class to implement the method
    }

}
