package eu.europa.esig.dss.pki.service;

import eu.europa.esig.dss.pki.exception.Error500Exception;
import eu.europa.esig.dss.pki.model.DBCertEntity;
import eu.europa.esig.dss.pki.utils.Utils;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Calendar;
import java.util.Date;
import java.util.List;


public class CRLGenerator {

    private static final Logger LOG = LoggerFactory.getLogger(CRLGenerator.class);
    private static CRLGenerator instance = null;
    //  @Autowired
    private static CertificateEntityService entityService;

    static {
        entityService = CertificateEntityService.getInstance();
    }

    private CRLGenerator() {
    }

    public static CRLGenerator getInstance() {
        if (instance == null) {
            synchronized (CRLGenerator.class) {
                instance = new CRLGenerator();
            }
        }
        return instance;
    }

    public byte[] getCRL(final DBCertEntity certEntity) {
        return getCRL(certEntity, new Date(), false);
    }

    public byte[] getCRL(final DBCertEntity certEntity, Date productionTime, boolean futur) {

        Calendar cal = Calendar.getInstance();
        if (futur) {
            cal.setTime(new Date());
        } else {
            cal.setTime(productionTime);
        }
        cal.add(Calendar.MONTH, 6);
        Date nextUpdate = cal.getTime();

        return generateCRL(certEntity, productionTime, nextUpdate);
    }

    public byte[] getCRL(final DBCertEntity certEntity, Date productionTime, Date nextUpdateTime) {
        return generateCRL(certEntity, productionTime, nextUpdateTime);
    }

    /**
     * @param certEntity     {@link DBCertEntity} of the CRL issuer
     * @param productionTime notBefore of the CRL. Current date if null
     * @param nextUpdateTime if true set notAfter 6 month after current date, if false set notAfter 6 month after production time
     */
    private byte[] generateCRL(final DBCertEntity certEntity, Date productionTime, Date nextUpdateTime) {
        try {
            X509CertificateHolder caCert = entityService.convertToX509CertificateHolder(certEntity);
            PrivateKey caPrivateKey = entityService.getPrivateKey(certEntity);
            List<DBCertEntity> children = entityService.getChildren(certEntity);

            String algo = Utils.getAlgorithmString(certEntity.getPrivateKeyAlgo(), certEntity.getDigestAlgo(), certEntity.isPss());

            if (productionTime == null) {
                productionTime = new Date();
            }
            X509v2CRLBuilder builder = new X509v2CRLBuilder(caCert.getSubject(), productionTime);
            builder.setNextUpdate(nextUpdateTime);

            for (DBCertEntity child : children) {
                if (child.getRevocationDate() != null) {
                    X509CertificateHolder entry = new X509CertificateHolder(child.getCertificate());
                    builder.addCRLEntry(entry.getSerialNumber(), child.getRevocationDate(), Utils.getCRLReason(child.getRevocationReason()));
                }
            }

            ContentSigner signer = new JcaContentSignerBuilder(algo).build(caPrivateKey);

            X509CRLHolder crl = builder.build(signer);

            return crl.getEncoded();
        } catch (IOException | OperatorCreationException e) {
            LOG.error("Unable to generate the CRL", e);
            throw new Error500Exception("Unable to generate the CRL");
        }
    }

    /**
     * Returns PEM encoded CRL
     *
     * @param certEntity {@link DBCertEntity} of the CRL issuer
     * @return PEM encoded CRL binaries
     */
    public byte[] getPemCRL(final DBCertEntity certEntity) {
        byte[] derCRL = getCRL(certEntity);
        return convertDerToPem(derCRL);
    }

    private byte[] convertDerToPem(byte[] derEncodedCRL) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            baos.write("-----BEGIN CRL-----\n".getBytes());

            Encoder encoder = Base64.getEncoder();
            byte[] base64Encoded = encoder.encode(derEncodedCRL);
            baos.write(base64Encoded);

            baos.write("\n-----END CRL-----".getBytes());

            return baos.toByteArray();
        } catch (IOException e) {
            LOG.error("Unable to generate the CRL", e);
            throw new Error500Exception("Unable to generate the CRL");
        }
    }

}
