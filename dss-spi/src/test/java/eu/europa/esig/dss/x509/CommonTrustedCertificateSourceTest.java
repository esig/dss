package eu.europa.esig.dss.x509;

import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.utils.Utils;

public class CommonTrustedCertificateSourceTest {

	@Test
	public void importKeyStore() {
		CommonTrustedCertificateSource ctcs = new CommonTrustedCertificateSource();

		KeyStoreCertificateSource keyStore = new KeyStoreCertificateSource("src/test/resources/keystore.jks", "dss-password");
		ctcs.importAsTrusted(keyStore);

		List<CertificateToken> certificates = ctcs.getCertificates();
		assertTrue(Utils.isCollectionNotEmpty(certificates));
	}

}
