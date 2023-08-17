package eu.europa.esig.dss.pki.service;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.constant.LoadProperties;
import eu.europa.esig.dss.pki.exception.Error500Exception;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.DBCertEntity;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;


public class KeystoreGenerator {
    public static final String PKI_FACTORY_KEYSTORE_PASSWORD = "pki.factory.keystore.password";
    private static final Logger LOG = LoggerFactory.getLogger(KeystoreGenerator.class);

    private static final String PKCS12 = "PKCS12";
    private static final String JKS = "JKS";
    CertEntityRepository certEntityRepository;

    private String password = LoadProperties.getValue(PKI_FACTORY_KEYSTORE_PASSWORD);

    public KeystoreGenerator(CertEntityRepository certEntityRepository) {
        this.certEntityRepository =certEntityRepository;
    }


    public byte[] getKeystore(String id) {
        CertEntity certEntity = certEntityRepository.getCertEntity(id);
        CertificateToken certificateToken = certEntity.getCertificateToken();
        String alias = DSSASN1Utils.getSubjectCommonName(certificateToken);
        PrivateKey privateKey = certEntity.getPrivateKeyObject();
        Certificate[] certificates=certEntity.getCertificateChain().stream().map(CertificateToken::getCertificate).toArray(Certificate[] ::new);

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            KeyStore ks = KeyStore.getInstance(PKCS12);
            ks.load(null, null);
            ks.setKeyEntry(alias, privateKey, password.toCharArray(),certificates);
            ks.store(baos, password.toCharArray());
            return baos.toByteArray();
        } catch (GeneralSecurityException | IOException e) {
            LOG.error("Unable to generate keystore for entry '" + id + "'", e);
            throw new Error500Exception("Unable to generate keystore");
        }
    }

    public byte[] getRoots() {
        List<CertEntity> roots = certEntityRepository.getByTrustAnchorTrue();
        return getJKS(roots);
    }

    public byte[] getTrustAnchors() {
        List<CertEntity> trustAnchors = certEntityRepository.getByTrustAnchorTrue();
        return getJKS(trustAnchors);
    }

    public byte[] getTrustAnchorsForPKI(String name) {
        List<CertEntity> trustAnchors = certEntityRepository.getByTrustAnchorTrueAndPkiName(name);
        return getJKS(trustAnchors);
    }

    public byte[] getToBeIgnored() {
        List<CertEntity> toBeIgnored = certEntityRepository.getByToBeIgnoredTrue();
        return getJKS(toBeIgnored);
    }

    private byte[] getJKS(List<CertEntity> certs) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            KeyStore ks = KeyStore.getInstance(JKS);
            ks.load(null, null);
            for (CertEntity cert : certs) {
                ks.setCertificateEntry(DSSASN1Utils.getSubjectCommonName(cert.getCertificateToken()), cert.getCertificateToken().getCertificate());
            }
            ks.store(baos, password.toCharArray());
            return baos.toByteArray();
        } catch (GeneralSecurityException | IOException e) {
            LOG.error("Unable to generate keystore with certs", e);
            throw new Error500Exception("Unable to generate keystore with certs");
        }
    }


}
