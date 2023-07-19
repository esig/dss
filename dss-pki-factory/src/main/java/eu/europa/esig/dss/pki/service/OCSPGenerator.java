package eu.europa.esig.dss.pki.service;

import eu.europa.esig.dss.pki.DigestAlgo;
import eu.europa.esig.dss.pki.RevocationReason;
import eu.europa.esig.dss.pki.db.Db;
import eu.europa.esig.dss.pki.exception.Error404Exception;
import eu.europa.esig.dss.pki.exception.Error500Exception;
import eu.europa.esig.dss.pki.model.DBCertEntity;
import eu.europa.esig.dss.pki.utils.Utils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.util.Date;

/**
 * Service used for OCSP Response generation
 */
public class OCSPGenerator {

    private static final Logger LOG = LoggerFactory.getLogger(OCSPGenerator.class);
    private static CertificateEntityService entityService = null;
    private static OCSPGenerator ocspGenerator = null;

    private OCSPGenerator() {

    }

    public static OCSPGenerator getInstance() {
        if (ocspGenerator == null) {
            synchronized (OCSPGenerator.class) {
                ocspGenerator=new OCSPGenerator();
                entityService = CertificateEntityService.getInstance();
            }
        }
        return ocspGenerator;
    }


    /**
     * Returns an OCSP Response for a {@code DBCertEntity} certificate according to the given {@code inputStream} request
     *
     * @param certEntity  {@link DBCertEntity} representing a certificate database entry to get an OCSP response for
     * @param inputStream {@link InputStream} OCSP request
     * @return OCSP response binaries
     */
    public byte[] getOCSPResponse(final DBCertEntity certEntity, InputStream inputStream) {
        return getCustomOCSPResponse(certEntity, new Date(), inputStream);
    }

    /**
     * Returns an OCSP Response with a custom {@code productionDate}
     *
     * @param certEntity     {@link DBCertEntity} representing a certificate database entry to get an OCSP response for
     * @param productionDate {@link Date} custom OCSP Response production time
     * @param inputStream    {@link InputStream} OCSP request
     * @return OCSP response binaries
     */
    public byte[] getCustomOCSPResponse(final DBCertEntity certEntity, Date productionDate, InputStream inputStream) {
        String algo = Utils.getAlgorithmString(certEntity.getPrivateKeyAlgo(), certEntity.getDigestAlgo(), certEntity.isPss());
        OCSPReq ocspReq = getOCSPReq(inputStream);
        return getCustomOCSPResponse(certEntity, ocspReq, algo, productionDate);
    }

    /**
     * Returns an OCSP Response with a custom {@code String} digest algorithm
     *
     * @param certEntity     {@link DBCertEntity} representing a certificate database entry to get an OCSP response for
     * @param ocspReq        {@link OCSPReq} OCSP Request object
     * @param algo           {@link String} digest algorithm name to produce OCSP with
     * @param productionDate {@link Date} custom OCSP Response production time
     * @return OCSP response binaries
     */
    public byte[] getCustomOCSPResponse(final DBCertEntity certEntity, OCSPReq ocspReq, String algo,
                                        Date productionDate) {
        X509CertificateHolder ocspCertificate = entityService.getOCSPCertificate(certEntity);
        X509CertificateHolder[] ocspCertificateChain = entityService.getOCSPCertificateChain(certEntity);
        PrivateKey ocspPrivateKey = entityService.getOCSPPrivateKey(certEntity);

        BasicOCSPRespBuilder builder = initBuilder(ocspCertificate);

        for (Req r : ocspReq.getRequestList()) {
            long serialNumber = r.getCertID().getSerialNumber().longValue();
            DBCertEntity entity = entityService.getBySerialNumberAndParent(serialNumber, certEntity.getSubject());
            if (entity == null) {
                throw new Error404Exception("Entity '" + serialNumber + "' not found for CA '" + certEntity.getSubject() + "'");
            } else if (entity.isSuspended()) {
                builder.addResponse(r.getCertID(), new UnknownStatus());
            } else if (entity.getRevocationDate() == null) {
                builder.addResponse(r.getCertID(), CertificateStatus.GOOD);
            } else {
                builder.addResponse(r.getCertID(), new RevokedStatus(entity.getRevocationDate(), Utils.getCRLReason(entity.getRevocationReason())));
            }
        }

        return generateOCSPResp(ocspCertificateChain, ocspPrivateKey, builder, productionDate, algo);
    }

    /**
     * Returns an OCSP response with a custom {@code productionDate}, {@code revocationDate} and {@code revocationReason}
     *
     * @param certEntity       {@link DBCertEntity} representing a certificate database entry to get an OCSP response for
     * @param productionDate   {@link Date} custom OCSP Response production time
     * @param revocationDate   {@link Date} custom certificate revocation time
     * @param revocationReason {@link RevocationReason} custom certificate revocation reason
     * @param inputStream      {@link InputStream} OCSP request
     * @return OCSP response binaries
     */
    public byte[] getCustomOCSPResponse(final DBCertEntity certEntity, Date productionDate, Date revocationDate,
                                        RevocationReason revocationReason, InputStream inputStream) {
        String algo = getCertEntitySignatureAlgorithm(certEntity);
        return getCustomOCSPResponse(certEntity, productionDate, revocationDate, revocationReason, algo, inputStream);
    }

    /**
     * Returns an OCSP response with a custom {@code productionDate}, {@code revocationDate}, {@code revocationReason}
     * and digest algorithm
     *
     * @param certEntity       {@link DBCertEntity} representing a certificate database entry to get an OCSP response for
     * @param productionDate   {@link Date} custom OCSP Response production time
     * @param revocationDate   {@link Date} custom certificate revocation time
     * @param revocationReason {@link RevocationReason} custom certificate revocation reason
     * @param algo             {@link String} digest algorithm name to produce OCSP with
     * @param inputStream      {@link InputStream} OCSP request
     * @return OCSP response binaries
     */
    public byte[] getCustomOCSPResponse(final DBCertEntity certEntity, Date productionDate, Date revocationDate,
                                        RevocationReason revocationReason, String algo, InputStream inputStream) {

        X509CertificateHolder ocspCertificate = entityService.getOCSPCertificate(certEntity);
        X509CertificateHolder[] ocspCertificateChain = entityService.getOCSPCertificateChain(certEntity);
        PrivateKey ocspPrivateKey = entityService.getOCSPPrivateKey(certEntity);

        OCSPReq ocspReq = getOCSPReq(inputStream);

        BasicOCSPRespBuilder builder = initBuilder(ocspCertificate);

        for (Req r : ocspReq.getRequestList()) {
            builder.addResponse(r.getCertID(), new RevokedStatus(revocationDate, Utils.getCRLReason(revocationReason)));
        }

        return generateOCSPResp(ocspCertificateChain, ocspPrivateKey, builder, productionDate, algo);
    }

    private byte[] generateOCSPResp(X509CertificateHolder[] ocspCertificateChain, PrivateKey ocspPrivateKey, BasicOCSPRespBuilder builder,
                                    Date productionDate, String algo) {
        try {
            ContentSigner signer = new JcaContentSignerBuilder(algo).build(ocspPrivateKey);

            OCSPRespBuilder respBuilder = new OCSPRespBuilder();
            OCSPResp ocspResp = respBuilder.build(OCSPRespBuilder.SUCCESSFUL, builder.build(signer, ocspCertificateChain, productionDate));

            return ocspResp.getEncoded();
        } catch (OperatorCreationException | OCSPException | IOException e) {
            LOG.error("Unable to generate the OCSP Response", e);
            throw new Error500Exception("Unable to generate the OCSP Response");
        }
    }

    /**
     * Generates and returns an OCSP Response produced with a digest algorithm based on
     * the digest algo used within a CertId of the OCSP request
     *
     * @param certEntity  {@link DBCertEntity} representing a certificate database entry to get an OCSP response for
     * @param inputStream {@link InputStream} OCSP request
     * @return OCSP response binaries
     */
    public byte[] getOCSPWithRequestAlgo(final DBCertEntity certEntity, InputStream inputStream) {
        OCSPReq ocspReq = getOCSPReq(inputStream);
        String algo = getRequestSignatureAlgorithm(certEntity, ocspReq);
        return getCustomOCSPResponse(certEntity, ocspReq, algo, new Date());
    }

    /**
     * Returns an internal error OCSP response
     *
     * @return response binaries
     */
    public byte[] getFailedOCSPResponse() {
        try {
            OCSPRespBuilder respBuilder = new OCSPRespBuilder();
            OCSPResp ocspResp = respBuilder.build(OCSPRespBuilder.INTERNAL_ERROR, null);
            return ocspResp.getEncoded();
        } catch (OCSPException | IOException e) {
            LOG.error("Unable to generate the OCSP Response with INTERNAL_ERROR code", e);
            throw new Error500Exception("Unable to generate the OCSP Response with INTERNAL_ERROR code");
        }
    }

    private OCSPReq getOCSPReq(InputStream inputStream) {
        try {
            return new OCSPReq(IOUtils.toByteArray(inputStream));
        } catch (Exception e) {
            LOG.error("Unable to parse the OCSP Req", e);
            throw new Error500Exception("Unable to parse the OCSP Req");
        }
    }

    private String getCertEntitySignatureAlgorithm(DBCertEntity certEntity) {
        return Utils.getAlgorithmString(certEntity.getPrivateKeyAlgo(), certEntity.getDigestAlgo(), certEntity.isPss());
    }

    private String getRequestSignatureAlgorithm(DBCertEntity certEntity, OCSPReq ocspReq) {
        String digestAlgorithm = getRequestDigestAlgorithm(ocspReq);
        if (digestAlgorithm == null) {
            digestAlgorithm = certEntity.getDigestAlgo();
        }
        return Utils.getAlgorithmString(certEntity.getPrivateKeyAlgo(), digestAlgorithm, certEntity.isPss());
    }

    private String getRequestDigestAlgorithm(OCSPReq ocspReq) {
        Req[] requestList = ocspReq.getRequestList();
        if (requestList != null && requestList.length > 0) {
            ASN1ObjectIdentifier hashAlgOID = requestList[0].getCertID().getHashAlgOID();
            if (hashAlgOID != null) {
                try {
                    MessageDigest messageDigest = MessageDigest.getInstance(hashAlgOID.getId(), BouncyCastleProvider.PROVIDER_NAME);
                    String digestAlgoJavaName = messageDigest.getAlgorithm();
                    if (digestAlgoJavaName != null) {
                        DigestAlgo digestAlgo = Utils.getDigestAlgoByJavaName(digestAlgoJavaName);
                        if (digestAlgo != null) {
                            return digestAlgo.value();
                        }
                    }
                } catch (NoSuchAlgorithmException e) {
                    LOG.warn("Unsupported DigestAlgorithm with OID : '{}'.", hashAlgOID.getId());
                } catch (NoSuchProviderException e) {
                    LOG.error("Unable to initialize BC Provider : '{}'.", e.getMessage(), e);
                } catch (Exception e) {
                    LOG.error("An error occurred while extraction a digest algorithm : {}", e.getMessage(), e);
                }
            }
        }
        return null;
    }

    private BasicOCSPRespBuilder initBuilder(X509CertificateHolder ocspCertificate) {
        try {
            AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

            SubjectPublicKeyInfo info = ocspCertificate.getSubjectPublicKeyInfo();

            return new BasicOCSPRespBuilder(info, new BcDigestCalculatorProvider().get(digAlgId));
        } catch (OCSPException | OperatorCreationException e) {
            LOG.error("Unable to init the OCSPRespBuilder", e);
            throw new Error500Exception("Unable to init the OCSPRespBuilder");
        }
    }

}
