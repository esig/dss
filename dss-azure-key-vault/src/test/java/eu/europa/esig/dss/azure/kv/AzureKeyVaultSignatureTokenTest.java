package eu.europa.esig.dss.azure.kv;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;

import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for AzureKeyVaultSignatureTokenConnection using Mockito stubs.
 */
public class AzureKeyVaultSignatureTokenTest {

    private CryptographyClient cryptoMock;
    private AzureKeyVaultSignatureTokenConnection token;
    private CertificateToken certToken;

    @BeforeEach
    void setUp() throws Exception {
        // Load a dummy certificate from test resources
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(getClass().getResourceAsStream("/test-cert.der"));
        certToken = new CertificateToken(cert);

        // Mock cryptography client
        cryptoMock = mock(CryptographyClient.class);
        SignResult signResult = new SignResult(
                new byte[]{0x01, 0x02},
                com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm.RS256,
                "kid"
        );
        when(cryptoMock.signData(any(), any())).thenReturn(signResult);

        // Use a special constructor for testing (you can add this to your production class)
        token = new AzureKeyVaultSignatureTokenConnection(cryptoMock, new CertificateToken[]{certToken});
    }

    @Test
    void testGetKeysReturnsCertificate() {
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        assertEquals(1, keys.size());
        CertificateToken returned = keys.get(0).getCertificate();
        assertNotNull(returned);
        assertEquals(certToken, returned);
    }

    @Test
    void testSignProducesSignatureValue() {
        ToBeSigned data = new ToBeSigned("hello".getBytes());
        SignatureValue sigVal = token.sign(data, DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256);
        assertNotNull(sigVal);
        assertEquals(SignatureAlgorithm.RSA_SHA256, sigVal.getAlgorithm());
        assertArrayEquals(new byte[]{0x01, 0x02}, sigVal.getValue());
    }

    @Test
    void testKeyStoreContainsCertificate() throws Exception {
        KeyStore ks = token.getKeyStore();
        assertTrue(ks.containsAlias("azure-cert"));
        assertNotNull(ks.getCertificate("azure-cert"));
    }
}
