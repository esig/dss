package pkifactory;

import eu.europa.esig.dss.pki.db.JaxbCertEntityRepository;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.pki.service.CertificateEntityService;
import eu.europa.esig.dss.pki.service.KeystoreGenerator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;

import static org.junit.jupiter.api.Assertions.*;

public class PkiFactoryApplicationTests {

    private CertificateEntityService entityService = CertificateEntityService.getInstance();
    private CertEntityRepository certEntityRepository= JaxbCertEntityRepository.getInstance();
    private KeystoreGenerator generator = new KeystoreGenerator(certEntityRepository);

    @BeforeAll
    public static void contextLoads() {

    }

    @Test
    public void getKS() {
        assertNotNull(generator.getKeystore("good-user"));
        assertNotNull(generator.getKeystore("cc-good-user-crossed"));
        assertNotNull(generator.getKeystore("cc-good-user-trusted"));
    }

    @Test
    public void testCrossCert() throws GeneralSecurityException, IOException {
        String keyCert = "cc-good-ca-crossed";
        byte[] keystore = generator.getKeystore(keyCert);
        assertNotNull(keystore);
        Certificate[] chain1 = getCertChain(keystore, keyCert);

        keyCert = "cc-good-ca-trusted";
        byte[] keystore2 = generator.getKeystore(keyCert);
        assertNotNull(keystore2);
        Certificate[] chain2 = getCertChain(keystore2, keyCert);

        assertNotEquals(chain1.length, chain2.length);

        X509CertificateHolder[] holders1 = getHolders(chain1);
        X509CertificateHolder[] holders2 = getHolders(chain2);

        X509CertificateHolder root1 = getCCRoot(holders1);
        assertNotNull(root1);
        assertNotNull(root1.getSubjectPublicKeyInfo());

        X509CertificateHolder root2 = getCCRoot(holders2);
        assertNotNull(root2);
        assertNotNull(root2.getSubjectPublicKeyInfo());

        assertArrayEquals(root1.getSubjectPublicKeyInfo().getEncoded(), root2.getSubjectPublicKeyInfo().getEncoded());
    }

    private X509CertificateHolder getCCRoot(X509CertificateHolder[] holders) {
        for (X509CertificateHolder x509CertificateHolder : holders) {
            if (entityService.getCommonName(x509CertificateHolder).equals("cc-root-ca")) {
                return x509CertificateHolder;
            }
        }
        return null;
    }

    private X509CertificateHolder[] getHolders(Certificate[] chain) throws GeneralSecurityException, IOException {
        X509CertificateHolder[] result = new X509CertificateHolder[chain.length];
        int i = 0;
        for (Certificate certificate : chain) {
            result[i] = new X509CertificateHolder(certificate.getEncoded());
            i++;
        }
        return result;
    }

    private Certificate[] getCertChain(byte[] keystore, String keyCert) throws GeneralSecurityException, IOException {
        KeyStore instance = KeyStore.getInstance("PKCS12");
        instance.load(new ByteArrayInputStream(keystore), "ks-password".toCharArray());
        return instance.getCertificateChain(keyCert);
    }
}
