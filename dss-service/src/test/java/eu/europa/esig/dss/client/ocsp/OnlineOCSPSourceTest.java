package eu.europa.esig.dss.client.ocsp;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.SecureRandomNonceSource;
import eu.europa.esig.dss.client.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.ocsp.OCSPToken;

public class OnlineOCSPSourceTest {

	private CertificateToken certificateToken;
	private CertificateToken rootToken;

	@Before
	public void init() {
		certificateToken = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		rootToken = DSSUtils.loadCertificate(new File("src/test/resources/CALT.crt"));
	}

	@Test
	public void testOCSPWithoutNonce() {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		ocspSource.setDataLoader(new OCSPDataLoader());
		OCSPToken ocspToken = ocspSource.getOCSPToken(certificateToken, rootToken);
		assertNotNull(ocspToken);
		assertNotNull(ocspToken.getBasicOCSPResp());
		assertFalse(ocspToken.isUseNonce());
	}

	@Test
	public void testOCSPWithNonce() {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		ocspSource.setDataLoader(new OCSPDataLoader());
		ocspSource.setNonceSource(new SecureRandomNonceSource());
		OCSPToken ocspToken = ocspSource.getOCSPToken(certificateToken, rootToken);
		assertNotNull(ocspToken);
		assertTrue(ocspToken.isUseNonce());
		assertTrue(ocspToken.isNonceMatch());
	}

}
