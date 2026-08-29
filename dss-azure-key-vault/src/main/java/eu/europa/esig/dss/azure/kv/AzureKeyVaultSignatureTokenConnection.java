package eu.europa.esig.dss.azure.kv;

import eu.europa.esig.dss.token.AbstractKeyStoreTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Objects;

public class AzureKeyVaultSignatureTokenConnection extends AbstractKeyStoreTokenConnection {

    private final CryptographyClient crypto;
    private final CertificateToken[] chain;

    public AzureKeyVaultSignatureTokenConnection(String vaultUrl, String keyId, String certName) {
        this(vaultUrl, keyId, certName, new DefaultAzureCredentialBuilder().build());
    }

    
    AzureKeyVaultSignatureTokenConnection(CryptographyClient crypto, CertificateToken[] chain) {
        this.crypto = crypto;
        this.chain = chain;
    }


    public AzureKeyVaultSignatureTokenConnection(String vaultUrl, String keyId, String certName, TokenCredential credential) {
        Objects.requireNonNull(vaultUrl, "vaultUrl");
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(certName, "certName");
        Objects.requireNonNull(credential, "credential");

        this.crypto = new CryptographyClientBuilder()
            .credential(credential)
            .keyIdentifier(keyId)
            .buildClient();

        CertificateClient certClient = new CertificateClientBuilder()
            .vaultUrl(vaultUrl)
            .credential(credential)
            .buildClient();

        KeyVaultCertificateWithPolicy kvCert = certClient.getCertificate(certName);
        byte[] cer = kvCert.getCer();
        if (cer == null || cer.length == 0) {
            throw new IllegalStateException("Key Vault certificate has no DER-encoded content");
        }
        this.chain = parseLeaf(cer);
    }

    private CertificateToken[] parseLeaf(byte[] leafDer) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate leaf = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(leafDer));
            return new CertificateToken[] { new CertificateToken(leaf) };
        } catch (Exception e) {
            throw new IllegalStateException("Unable to parse X.509 certificate from Key Vault", e);
        }
    }

    public SignatureValue sign(ToBeSigned dataToSign, DigestAlgorithm digestAlgo, SignatureAlgorithm sigAlgo) {
        com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm kvAlgo = mapSignatureAlgorithm(sigAlgo);
        SignResult result = crypto.signData(kvAlgo, dataToSign.getBytes());
        return new SignatureValue(sigAlgo, result.getSignature());
    }

    @Override
    public java.util.List<DSSPrivateKeyEntry> getKeys() {
        DSSPrivateKeyEntry entry = new DSSPrivateKeyEntry() {
            @Override
            public CertificateToken getCertificate() {
                return chain[0];
            }

            @Override
            public CertificateToken[] getCertificateChain() {
                return chain;
            }

            @Override
            public EncryptionAlgorithm getEncryptionAlgorithm() {
                String algo = chain[0].getCertificate().getPublicKey().getAlgorithm();
                return "EC".equalsIgnoreCase(algo) ? EncryptionAlgorithm.ECDSA : EncryptionAlgorithm.RSA;
            }

            // helper method, not overriding
            public SignatureValue sign(ToBeSigned dataToSign, DigestAlgorithm digestAlgo, SignatureAlgorithm sigAlgo) {
                com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm kvAlgo = mapSignatureAlgorithm(sigAlgo);
                SignResult result = crypto.signData(kvAlgo, dataToSign.getBytes());
                return new SignatureValue(sigAlgo, result.getSignature());
            }
        };
        return java.util.Collections.singletonList(entry);
    }

    @Override
    protected KeyStore.PasswordProtection getKeyProtectionParameter() {
        return new KeyStore.PasswordProtection(new char[0]);
    }

    @Override
    protected KeyStore getKeyStore() {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setCertificateEntry("azure-cert", chain[0].getCertificate());
            return ks;
        } catch (Exception e) {
            throw new IllegalStateException("Unable to create KeyStore", e);
        }
    }

    @Override
    public void close() {
        // Nothing to close
    }

    private com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm mapSignatureAlgorithm(SignatureAlgorithm sigAlgo) {
        switch (sigAlgo) {
            case RSA_SHA256: return com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm.RS256;
            case RSA_SHA384: return com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm.RS384;
            case RSA_SHA512: return com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm.RS512;
            
            case ECDSA_SHA256: return com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm.ES256;
            case ECDSA_SHA384: return com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm.ES384;
            case ECDSA_SHA512: return com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm.ES512;

            default:
                throw new UnsupportedOperationException("Unsupported signature algorithm: " + sigAlgo);
        }
    }
}
