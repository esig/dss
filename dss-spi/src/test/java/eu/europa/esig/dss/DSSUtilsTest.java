package eu.europa.esig.dss;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.BeforeClass;
import org.junit.Test;

import eu.europa.esig.dss.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.x509.CertificateToken;

public class DSSUtilsTest {

	private static CertificateToken certificateWithAIA;

	@BeforeClass
	public static void init() {
		certificateWithAIA = DSSUtils.loadCertificate(new File("src/test/resources/TSP_Certificate_2014.crt"));
		assertNotNull(certificateWithAIA);
	}

	@Test
	public void testLoadIssuer() {
		CertificateToken issuer = DSSUtils.loadIssuerCertificate(certificateWithAIA, new NativeHTTPDataLoader());
		assertNotNull(issuer);
		assertTrue(certificateWithAIA.isSignedBy(issuer));
	}

	@Test
	public void testLoadIssuerEmptyDataLoader() {
		assertNull(DSSUtils.loadIssuerCertificate(certificateWithAIA, null));
	}

	@Test
	public void testLoadIssuerNoAIA() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));
		assertNull(DSSUtils.loadIssuerCertificate(certificate, new NativeHTTPDataLoader()));
	}
}
