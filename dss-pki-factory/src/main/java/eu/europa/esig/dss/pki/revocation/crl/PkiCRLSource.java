package eu.europa.esig.dss.pki.revocation.crl;

import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.exception.Error500Exception;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.Revocation;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.pki.utils.PkiUtils;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
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
import java.util.Objects;

/**
 * An implementation of the CRLSource interface that provides methods to obtain Certificate Revocation Lists (CRLs)
 * for certificate revocation checks. The CRLs are retrieved based on the CertEntity (certificate entity) and
 * optionally specified production and next update dates.
 */
public class PkiCRLSource implements CRLSource {

    private static final Logger LOG = LoggerFactory.getLogger(PkiCRLSource.class);
    private static final long serialVersionUID = 6912729291417315212L;

    private CertEntity certEntity;
    private Date productionDate;
    private Date nextUpdate;

    private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
    private MaskGenerationFunction maskGenerationFunction;
    private CertEntityRepository certEntityRepository;

    /**
     * Constructs a PkiCRLSource with the specified CertEntity.
     *
     * @param certEntity           The CertEntity for which CRLs will be obtained.
     * @param certEntityRepository The CertEntity for which CRLs will be obtained.
     */
    public PkiCRLSource(CertEntityRepository certEntityRepository, CertEntity certEntity) {
        this.certEntityRepository = certEntityRepository;
        this.certEntity = certEntity;
    }


    public PkiCRLSource(CertEntityRepository certEntityRepository) {
        this.certEntityRepository = certEntityRepository;
    }


    /**
     * Retrieves a Certificate Revocation List (CRL) token for the given certificate and its issuer certificate if the CertEntity is not already.
     *
     * @param certificateToken       The CertificateToken representing the certificate to be checked for revocation.
     * @param issuerCertificateToken The CertificateToken representing the issuer certificate of the certificate to be verified.
     * @return The CRLToken representing the revocation status of the certificate.
     * @throws NullPointerException If either certificateToken or issuerCertificateToken is null.
     * @throws RuntimeException     If an error occurs during the CRL retrieval or validation process.
     */
    @Override
    public CRLToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) throws NullPointerException, RuntimeException {
        Objects.requireNonNull(certificateToken, "Certificate cannot be null");
        Objects.requireNonNull(nextUpdate, "NextUpdateDate cannot be null");
        Objects.requireNonNull(issuerCertificateToken, "The issuer of the certificate to be verified cannot be null");

        // If the CertEntity is not already set, retrieve it based on the issuer certificate and certificate subject.
        if (certEntity == null) {
            certEntity = certEntityRepository.getByCertificateToken(issuerCertificateToken);
        }

        // Obtain the CRL bytes based on the productionDate and nextUpdate parameters.
        byte[] crlBytes = getCRL(certEntity, productionDate, nextUpdate);

        final CRLValidity crlValidity;

        try {
            // Build the CRLValidity using CRLUtils from the retrieved CRL bytes and the issuerCertificateToken.
            crlValidity = CRLUtils.buildCRLValidity(CRLUtils.buildCRLBinary(crlBytes), issuerCertificateToken);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Create a new CRLToken with the certificateToken and the CRLValidity, and set its origin as external.
        final CRLToken crlToken = new CRLToken(certificateToken, crlValidity);
        crlToken.setExternalOrigin(RevocationOrigin.EXTERNAL);
        return crlToken;
    }


    private byte[] generateCRL(final CertEntity certEntity, Date productionTime, Date nextUpdateTime) {
        try {

            X509CertificateHolder caCert = DSSASN1Utils.getX509CertificateHolder(certEntity.getCertificateToken());

            List<Revocation> revocationList = certEntityRepository.getRevocationList(certEntity);

            SignatureAlgorithm algorithm = SignatureAlgorithm.getAlgorithm(certEntity.getEncryptionAlgorithm(), digestAlgorithm, maskGenerationFunction);

            if (productionTime == null) {
                productionTime = new Date();
            }
            X509v2CRLBuilder builder = new X509v2CRLBuilder(caCert.getSubject(), productionTime);
            builder.setNextUpdate(nextUpdateTime);

            addRevocationsToCRL(builder, revocationList);

            Objects.requireNonNull(algorithm, "SignatureAlgorithm cannot be null!");
            ContentSigner signer = new JcaContentSignerBuilder(algorithm.getJCEId()).build(certEntity.getPrivateKeyObject());

            X509CRLHolder crl = builder.build(signer);

            return crl.getEncoded();
        } catch (IOException | OperatorCreationException e) {
            LOG.error("Unable to generate the CRL", e);
            throw new Error500Exception("Unable to generate the CRL");
        }
    }

    /**
     * Adds revocations to the CRL builder based on the provided CertEntity and revocationList.
     *
     * @param revocationList List of Revocation objects containing the revocation information.
     * @param builder        The X509v2CRLBuilder instance to which the entries will be added.
     * @return List of added CRLEntry objects.
     */

    protected void addRevocationsToCRL(X509v2CRLBuilder builder, List<Revocation> revocationList) {
        revocationList.forEach(revocation -> {
            X509CertificateHolder entry = DSSASN1Utils.getX509CertificateHolder(revocation.getDbCertEntity().getCertificateToken());
            builder.addCRLEntry(entry.getSerialNumber(), revocation.getRevocationDate(), PkiUtils.getCRLReason(revocation.getRevocationReason()));
        });
    }


    /**
     * Generates a CRL (Certificate Revocation List) for the specified CertEntity with the provided production time and next update time.
     *
     * @param certEntity     The CertEntity of the CRL issuer.
     * @param productionTime The notBefore (validity start) date of the CRL. If null, the current date is used.
     * @param nextUpdateTime The notAfter (validity end) date of the CRL. If true, set notAfter 6 months after the current date; if false, set notAfter 6 months after the production time.
     * @return The generated CRL in byte array format.
     */
    public byte[] getCRL(final CertEntity certEntity, Date productionTime, Date nextUpdateTime) {
        return generateCRL(certEntity, productionTime, nextUpdateTime);
    }

    /**
     * Set the production date for the CRL generation.
     *
     * @param productionDate The production date to be set.
     */
    public void setProductionDate(Date productionDate) {
        this.productionDate = productionDate;
    }

    /**
     * Set the next update date for the CRL generation.
     *
     * @param nextUpdate The next update date to be set.
     */
    public void setNextUpdate(Date nextUpdate) {
        this.nextUpdate = nextUpdate;
    }

    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public void setMaskGenerationFunction(MaskGenerationFunction maskGenerationFunction) {
        this.maskGenerationFunction = maskGenerationFunction;
    }
}
