package eu.europa.esig.dss.pki.jaxb.service;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.List;


public class CertEntityKeystoreBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(CertEntityKeystoreBuilder.class);

    private String keyStoreType = "PKCS12";


    private List<CertEntity> keyEntries;

    private List<CertEntity> certificateEntries;

    private char[] keyEntryPassword;

    private char[] keyStorePassword;

    public byte[] build() {
        return new CertEntityKeystoreBuilder(keyStoreType, keyEntries, certificateEntries, keyEntryPassword, keyStorePassword).getKeystore();
    }

    private CertEntityKeystoreBuilder(String keyStoreType, List<CertEntity> keyEntries, List<CertEntity> certificateEntries, char[] keyEntryPassword, char[] keyStorePassword) {
        this.keyStoreType = keyStoreType;
        this.keyEntries = keyEntries;
        this.certificateEntries = certificateEntries;
        this.keyEntryPassword = keyEntryPassword;
        this.keyStorePassword = keyStorePassword;
    }

    public CertEntityKeystoreBuilder() {
    }

    public byte[] getKeystore() {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            KeyStore ks = KeyStore.getInstance(keyStoreType);
            ks.load(null, null);
            if (Utils.isCollectionNotEmpty(keyEntries)) {
                for (CertEntity certEntity : keyEntries) {

                    CertificateToken certificateToken = certEntity.getCertificateToken();
                    String alias = DSSASN1Utils.getSubjectCommonName(certificateToken);
                    PrivateKey privateKey = certEntity.getPrivateKeyObject();
                    Certificate[] certificates = certEntity.getCertificateChain().stream().map(CertificateToken::getCertificate).toArray(Certificate[]::new);
                    ks.setKeyEntry(alias, privateKey, keyEntryPassword, certificates);
                }
            }
            if (Utils.isCollectionNotEmpty(certificateEntries)) {

                for (CertEntity cert : certificateEntries) {
                    ks.setCertificateEntry(DSSASN1Utils.getSubjectCommonName(cert.getCertificateToken()), cert.getCertificateToken().getCertificate());
                }
            }
            ks.store(baos, keyStorePassword);
            return baos.toByteArray();
        } catch (GeneralSecurityException | IOException e) {
            LOG.error("Unable to generate keystore with certs", e);
            throw new DSSException("Unable to generate keystore");
        }
    }


    public CertEntityKeystoreBuilder setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
        return this;
    }

    public CertEntityKeystoreBuilder setKeyEntries(List<CertEntity> keyEntries) {
        this.keyEntries = keyEntries;
        return this;
    }

    public CertEntityKeystoreBuilder setCertificateEntries(List<CertEntity> certificateEntries) {
        this.certificateEntries = certificateEntries;
        return this;
    }

    public CertEntityKeystoreBuilder setKeyEntryPassword(char[] keyEntryPassword) {
        this.keyEntryPassword = keyEntryPassword;
        return this;
    }

    public CertEntityKeystoreBuilder setKeyStorePassword(char[] keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
        return this;
    }


}
