package eu.europa.ec.markt.dss.validation102853.ocsp;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.Before;
import org.junit.Test;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.NonceSource;
import eu.europa.ec.markt.dss.validation102853.OCSPToken;
import eu.europa.ec.markt.dss.validation102853.loader.NativeHTTPDataLoader;

public class OnlineOCSPSourceTest {

	private CertificateToken certificateToken;
	private CertificateToken rootToken;

	@Before
	public void init() {
		certificateToken = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		rootToken = DSSUtils.loadCertificate(new File("src/test/resources/LTQCACA.crt"));

		// Init the issuer required for tests
		assertTrue(certificateToken.isSignedBy(rootToken));
	}

	@Test
	public void testOCSPWithoutNonce() {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		ocspSource.setDataLoader(new NativeHTTPDataLoader());
		OCSPToken ocspToken = ocspSource.getOCSPToken(certificateToken);
		assertNotNull(ocspToken);
	}

	@Test
	public void testOCSPWithNonce() {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		ocspSource.setDataLoader(new NativeHTTPDataLoader());
		ocspSource.setNonceSource(new NonceSource());
		OCSPToken ocspToken = ocspSource.getOCSPToken(certificateToken);
		assertNotNull(ocspToken);
	}
}
