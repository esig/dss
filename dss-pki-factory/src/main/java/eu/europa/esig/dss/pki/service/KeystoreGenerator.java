package eu.europa.esig.dss.pki.service;

import eu.europa.esig.dss.pki.constant.LoadProperties;
import eu.europa.esig.dss.pki.exception.Error500Exception;
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
import java.util.List;


public class KeystoreGenerator {
    public static final String PKI_FACTORY_KEYSTORE_PASSWORD = "pki.factory.keystore.password";
    private static KeystoreGenerator instance = null;
    private static final Logger LOG = LoggerFactory.getLogger(KeystoreGenerator.class);

    private static final String PKCS12 = "PKCS12";
    private static final String JKS = "JKS";

    private static CertificateEntityService entityService = null;
    private String password = LoadProperties.getValue(PKI_FACTORY_KEYSTORE_PASSWORD);

    private KeystoreGenerator() {
    }

    public static KeystoreGenerator getInstance() {
        if (instance == null) {
            synchronized (KeystoreGenerator.class) {
                instance = new KeystoreGenerator();
                entityService = CertificateEntityService.getInstance();
            }
        }
        return instance;
    }


    public byte[] getKeystore(String id) {

        X509CertificateHolder certificate = entityService.getCertificate(id);
        X509CertificateHolder[] certificateChain = entityService.getCertificateChain(id);
        PrivateKey privateKey = entityService.getPrivateKey(id);

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            KeyStore ks = KeyStore.getInstance(PKCS12);
            ks.load(null, null);
            ks.setKeyEntry(entityService.getCommonName(certificate), privateKey, password.toCharArray(), getCertificates(certificateChain));
            ks.store(baos, password.toCharArray());
            return baos.toByteArray();
        } catch (GeneralSecurityException | IOException e) {
            LOG.error("Unable to generate keystore for entry '" + id + "'", e);
            throw new Error500Exception("Unable to generate keystore");
        }
    }

    public byte[] getRoots() {
        List<X509CertificateHolder> roots = entityService.getRoots();
        return getJKS(roots);
    }

    public byte[] getTrustAnchors() {
        List<X509CertificateHolder> trustAnchors = entityService.getTrustAnchors();
        return getJKS(trustAnchors);
    }

    public byte[] getTrustAnchorsForPKI(String name) {
        List<X509CertificateHolder> trustAnchors = entityService.getTrustAnchorsForPKI(name);
        return getJKS(trustAnchors);
    }

    public byte[] getToBeIgnored() {
        List<X509CertificateHolder> toBeIgnored = entityService.getToBeIgnored();
        return getJKS(toBeIgnored);
    }

    private byte[] getJKS(List<X509CertificateHolder> certs) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            KeyStore ks = KeyStore.getInstance(JKS);
            ks.load(null, null);
            for (X509CertificateHolder cert : certs) {
                ks.setCertificateEntry(entityService.getCommonName(cert), entityService.convert(cert));
            }
            ks.store(baos, password.toCharArray());
            return baos.toByteArray();
        } catch (GeneralSecurityException | IOException e) {
            LOG.error("Unable to generate keystore with certs", e);
            throw new Error500Exception("Unable to generate keystore with certs");
        }
    }

    private Certificate[] getCertificates(X509CertificateHolder[] certificateChain) throws CertificateException {
        Certificate[] chain = new Certificate[certificateChain.length];
        int i = 0;
        for (X509CertificateHolder x509CertificateHolder : certificateChain) {
            chain[i] = entityService.convert(x509CertificateHolder);
            i++;
        }
        return chain;
    }

}
