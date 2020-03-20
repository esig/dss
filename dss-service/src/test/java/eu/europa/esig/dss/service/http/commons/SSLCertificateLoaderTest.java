package eu.europa.esig.dss.service.http.commons;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;

public class SSLCertificateLoaderTest {
	
	@Test
	public void test() throws Exception {
		String url = "https://wikipedia.org";

		SSLCertificateLoader sslCertificateDataLoader = new SSLCertificateLoader();
		List<CertificateToken> certificateTokens = sslCertificateDataLoader.getCertificates(url);
		assertTrue(Utils.isCollectionNotEmpty(certificateTokens));
	}
	
	@Test
	public void wrongUrl() throws Exception {
		String url = "https://wrong.url";

		SSLCertificateLoader sslCertificateDataLoader = new SSLCertificateLoader();
		DSSException exception = assertThrows(DSSException.class, () -> sslCertificateDataLoader.getCertificates(url));
		assertTrue(exception.getMessage().contains("Unable to process GET call for url [https://wrong.url]"));
	}
	
	@Test
	public void ldapUrl() throws Exception {
		String url = "ldap://crl-source.hn/o=Hello";

		SSLCertificateLoader sslCertificateDataLoader = new SSLCertificateLoader();
		DSSException exception = assertThrows(DSSException.class, () -> sslCertificateDataLoader.getCertificates(url));
		assertEquals("DSS framework only supports HTTP(S) certificate extraction", exception.getMessage());
	}

}
