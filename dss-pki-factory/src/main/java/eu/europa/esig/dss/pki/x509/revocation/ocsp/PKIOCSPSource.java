package eu.europa.esig.dss.pki.x509.revocation.ocsp;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.CertEntityRevocation;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * The PkiOCSPSource class implements the OCSPSource interface for obtaining revocation tokens.
 * It retrieves OCSP responses for a given certificate by sending OCSP requests to a specified OCSP responder.
 */
public class PKIOCSPSource implements OCSPSource {

    private static final Logger LOG = LoggerFactory.getLogger(PKIOCSPSource.class);


    private final CertEntityRepository certEntityRepository;
    private CertEntity certEntity;
    private Date productionDate;
    private Date revocationDate;
    private RevocationReason revocationReason;

    private MaskGenerationFunction maskGenerationFunction;


    /**
     * The Digest Algorithm of the signature of the created time-stamp token
     */
    protected DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;


    /**
     * Constructs a PkiOCSPSource instance with the provided CertEntity.
     *
     * @param certEntity The CertEntity for which the OCSP responses will be obtained.
     */
    public PKIOCSPSource(CertEntityRepository certEntityRepository, CertEntity certEntity) {
        this.certEntityRepository = certEntityRepository;
        this.certEntity = certEntity;

    }

    public PKIOCSPSource(CertEntityRepository certEntityRepository) {
        this.certEntityRepository = certEntityRepository;

    }

    /**
     * Retrieves the OCSP token for the revocation status of the given certificate.
     *
     * @param certificateToken       The CertificateToken representing the certificate for which the revocation status is to be checked.
     * @param issuerCertificateToken The CertificateToken representing the issuer certificate of the certificate to be verified.
     * @return An OCSPToken representing the OCSP response containing the revocation status of the certificate.
     * @throws RuntimeException If an error occurs during the OCSP request or response processing.
     */
    @Override
    public OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
        final String dssIdAsString = certificateToken.getDSSIdAsString();
        LOG.trace("--> PKIOCSPSource queried for {}", dssIdAsString);
        List<String> ocspAccessUrls = CertificateExtensionsUtils.getOCSPAccessUrls(certificateToken);
        if (Utils.isCollectionEmpty(ocspAccessUrls)) {
            LOG.warn("No OCSP location found for {}", dssIdAsString);
            return null;
        }
        final CertificateID certId = DSSRevocationUtils.getOCSPCertificateID(certificateToken, issuerCertificateToken, digestAlgorithm);

        try {

            CertEntity currentCertEntity = getCertEntity(issuerCertificateToken);
            //Objects.requireNonNull(currentCertEntity, "No certification found for the provided CertificateToken.");

            OCSPResp ocspRespBytes;
            OCSPReq ocspReq = buildOCSPRequest(certId);

            // Determine the OCSP response based on different scenarios
            ocspRespBytes = getCustomOCSPResponse(currentCertEntity, certificateToken, ocspReq);

            // Build the OCSP response and extract the latest single response

            BasicOCSPResp basicResponse = (BasicOCSPResp) ocspRespBytes.getResponseObject();
            SingleResp latestSingleResponse = DSSRevocationUtils.getLatestSingleResponse(basicResponse, certificateToken, issuerCertificateToken);

            // Create the OCSPToken using the OCSP response data
            OCSPToken ocspToken = new OCSPToken(basicResponse, latestSingleResponse, certificateToken, issuerCertificateToken);
            ocspToken.setExternalOrigin(RevocationOrigin.EXTERNAL);

            return ocspToken;

        } catch (OCSPException e) {
            throw new RuntimeException(e);
        }
    }

    protected CertEntity getCertEntity(CertificateToken issuerCertificateToken) {
        // If certEntity is not provided during construction, find it based on issuerCertificateToken and certificateToken
        CertEntity currentCertEntity;
        if (certEntity == null) {
            currentCertEntity = certEntityRepository.getByCertificateToken(issuerCertificateToken);
        } else {
            currentCertEntity = certEntity;
        }
        return currentCertEntity;
    }


    protected OCSPResp getCustomOCSPResponse(final CertEntity certEntity, CertificateToken certificateToken, OCSPReq ocspReq) {
        X509CertificateHolder ocspCertificate = DSSASN1Utils.getX509CertificateHolder(certEntity.getCertificateToken());
        X509CertificateHolder[] ocspCertificateChain = certEntityRepository.getCertificateChain(certEntity);

        PrivateKey ocspPrivateKey = certEntity.getPrivateKeyObject();

        BasicOCSPRespBuilder builder = initBuilder(ocspCertificate);


        addStatusToOCSPResponse(certificateToken, builder, Arrays.stream(ocspReq.getRequestList()).findFirst().orElseThrow(() -> new IllegalStateException("The ocsp request does not contain any request!")));

        Date productionDate = this.productionDate == null ? new Date() : this.productionDate;
        return generateOCSPResp(ocspCertificateChain, ocspPrivateKey, builder, productionDate, getCertEntitySignatureAlgorithm(certEntity));
    }

    protected void addStatusToOCSPResponse(CertificateToken certificateToken, BasicOCSPRespBuilder builder, Req r) {
        CertEntityRevocation certEntityRevocation = revocationReason != null && revocationDate != null ? new CertEntityRevocation(revocationDate, revocationReason) : certEntityRepository.getRevocation(certificateToken);

        addRevocationStatusToOCSPResponse(builder, r, certEntityRevocation);

    }

    protected void addRevocationStatusToOCSPResponse(BasicOCSPRespBuilder builder, Req r, CertEntityRevocation certEntityRevocation) {
        if (certEntityRevocation == null || certEntityRevocation.getRevocationDate() == null) {
            builder.addResponse(r.getCertID(), CertificateStatus.GOOD);
        } else {
            builder.addResponse(r.getCertID(), new RevokedStatus(certEntityRevocation.getRevocationDate(), certEntityRevocation.getRevocationReason().getValue()));
        }
    }


    protected OCSPResp generateOCSPResp(X509CertificateHolder[] ocspCertificateChain, PrivateKey ocspPrivateKey, BasicOCSPRespBuilder builder, Date productionDate, String algo) {
        try {
            ContentSigner signer = new JcaContentSignerBuilder(algo).build(ocspPrivateKey);

            OCSPRespBuilder respBuilder = new OCSPRespBuilder();
            OCSPResp ocspResp = respBuilder.build(OCSPRespBuilder.SUCCESSFUL, builder.build(signer, ocspCertificateChain, productionDate));

            return ocspResp;
        } catch (OperatorCreationException | OCSPException e) {
            LOG.error("Unable to generate the OCSP Response", e);
            throw new DSSException("Unable to generate the OCSP Response");
        }
    }


    protected OCSPResp getOCSPWithRequestAlgo(final CertEntity certEntity, CertificateToken certificateToken, OCSPReq ocspReq) {

        return getCustomOCSPResponse(certEntity, certificateToken, ocspReq);
    }


    private String getCertEntitySignatureAlgorithm(CertEntity certEntity) {
        return Objects.requireNonNull(SignatureAlgorithm.getAlgorithm(certEntity.getEncryptionAlgorithm(), digestAlgorithm, maskGenerationFunction)).getJCEId();
    }

    private BasicOCSPRespBuilder initBuilder(X509CertificateHolder ocspCertificate) {
        try {
            AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

            SubjectPublicKeyInfo info = ocspCertificate.getSubjectPublicKeyInfo();

            return new BasicOCSPRespBuilder(info, new BcDigestCalculatorProvider().get(digAlgId));
        } catch (OCSPException | OperatorCreationException e) {
            LOG.error("Unable to init the OCSPRespBuilder", e);
            throw new DSSException("Unable to init the OCSPRespBuilder");
        }
    }

    protected OCSPReq buildOCSPRequest(final CertificateID certId) throws DSSException {
        try {
            final OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
            ocspReqBuilder.addRequest(certId);

            final OCSPReq ocspReq = ocspReqBuilder.build();
            return ocspReq;

        } catch (OCSPException e) {
            throw new DSSException("Cannot build OCSP Request", e);
        }
    }

    /**
     * Sets the production date for generating OCSP responses.
     *
     * @param productionDate The production date for OCSP responses.
     */
    public void setProductionDate(Date productionDate) {
        this.productionDate = productionDate;
    }

    /**
     * Sets the revocation date for generating OCSP responses with custom revocation information.
     *
     * @param revocationDate The revocation date for OCSP responses with custom revocation information.
     */
    public void setRevocationDate(Date revocationDate) {
        this.revocationDate = revocationDate;
    }

    /**
     * Sets the revocation reason for generating OCSP responses with custom revocation information.
     *
     * @param revocationReason The revocation reason for OCSP responses with custom revocation information.
     */
    public void setRevocationReason(RevocationReason revocationReason) {
        this.revocationReason = revocationReason;
    }

    public void setMaskGenerationFunction(MaskGenerationFunction maskGenerationFunction) {
        this.maskGenerationFunction = maskGenerationFunction;
    }

    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public void setCertEntity(CertEntity certEntity) {
        this.certEntity = certEntity;
    }

    public CertEntityRepository getCertEntityRepository() {
        return certEntityRepository;
    }
}
