package eu.europa.esig.dss.x509;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.Test;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

public class KeyStoreCertificateSourceTest {

	private static final String KEYSTORE_PASSWORD = "dss-password";
	private static final String KEYSTORE_TYPE = "PKCS12";
	private static final String KEYSTORE_FILEPATH = "src/test/resources/keystore.p12";

	@Test
	public void testLoadAddAndDelete() {
		KeyStoreCertificateSource kscs = new KeyStoreCertificateSource(new File(KEYSTORE_FILEPATH), KEYSTORE_TYPE, KEYSTORE_PASSWORD);
		assertNotNull(kscs);

		int startSize = Utils.collectionSize(kscs.getCertificatesFromKeyStore());
		assertTrue(startSize > 0);

		CertificateToken token = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));
		kscs.addCertificateToKeyStore(token);

		int sizeAfterAdd = Utils.collectionSize(kscs.getCertificatesFromKeyStore());
		assertTrue(sizeAfterAdd == startSize + 1);
		String tokenId = token.getDSSIdAsString();

		CertificateToken certificate = kscs.getCertificate(tokenId);
		assertNotNull(certificate);

		kscs.deleteCertificateFromKeyStore(tokenId);

		int sizeAfterDelete = Utils.collectionSize(kscs.getCertificatesFromKeyStore());
		assertTrue(sizeAfterDelete == startSize);
	}

	@Test(expected = DSSException.class)
	public void wrongPassword() {
		KeyStoreCertificateSource kscs = new KeyStoreCertificateSource(new File(KEYSTORE_FILEPATH), KEYSTORE_TYPE, "wrong password");
		assertNotNull(kscs);

		kscs.getCertificatesFromKeyStore();
	}

	@Test(expected = DSSException.class)
	public void wrongFile() {
		KeyStoreCertificateSource kscs = new KeyStoreCertificateSource(new File("src/test/resources/keystore.p13"), KEYSTORE_TYPE, KEYSTORE_PASSWORD);
		assertNotNull(kscs);

		kscs.deleteCertificateFromKeyStore("1231456");
	}

}
