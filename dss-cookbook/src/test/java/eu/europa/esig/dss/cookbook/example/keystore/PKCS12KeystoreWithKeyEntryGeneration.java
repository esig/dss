package eu.europa.esig.dss.cookbook.example.keystore;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Date;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;

public class PKCS12KeystoreWithKeyEntryGeneration {

	private static final String KEYSTORE_TYPE = "PKCS12";
	private static final String KEYSTORE_FILEPATH = "target/keystore.p12";
	private static final String KEYSTORE_PASSWORD = "password";

	@Test
	public void generate() throws Exception {
		CertificateService service = new CertificateService();
		MockPrivateKeyEntry entry = service.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		KeyStore keystore = createKeyStore();
		addCertificate(keystore, "certificate", entry.getCertificate(), entry);

		OutputStream fos = new FileOutputStream(KEYSTORE_FILEPATH);
		keystore.store(fos, KEYSTORE_PASSWORD.toCharArray());

		AbstractSignatureTokenConnection signingToken = new Pkcs12SignatureToken(KEYSTORE_PASSWORD, KEYSTORE_FILEPATH);
		Assert.assertEquals(1, signingToken.getKeys().size());
		DSSPrivateKeyEntry privateEntry = signingToken.getKeys().get(0);
		Assert.assertNotNull(privateEntry);
	}

	private static void addCertificate(KeyStore store, String alias, CertificateToken cert, MockPrivateKeyEntry entry) throws Exception {
		if (cert.isExpiredOn(new Date())) {
			throw new RuntimeException("Alias " + alias + " is expired");
		}
		store.setCertificateEntry(alias, cert.getCertificate());
		Certificate[] chain = { store.getCertificate(alias) };
		store.setKeyEntry(alias, entry.getPrivateKey(), KEYSTORE_PASSWORD.toCharArray(), chain);
	}

	private KeyStore createKeyStore() throws Exception {
		KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
		keyStore.load(null, KEYSTORE_PASSWORD.toCharArray());
		OutputStream fos = new FileOutputStream(KEYSTORE_FILEPATH);
		keyStore.store(fos, KEYSTORE_PASSWORD.toCharArray());
		Utils.closeQuietly(fos);
		return keyStore;
	}
}
