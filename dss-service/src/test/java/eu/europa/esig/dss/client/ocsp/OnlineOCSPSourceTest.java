package eu.europa.esig.dss.client.ocsp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

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
		rootToken = DSSUtils.loadCertificate(new File("src/test/resources/LTQCACA.crt"));
	}

	@Test
	public void getAccessLocation() {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		ocspSource.setDataLoader(new OCSPDataLoader());
		assertNull(ocspSource.getAccessLocation(rootToken));
		assertEquals("http://ocsp.luxtrust.lu", ocspSource.getAccessLocation(certificateToken));
	}

	@Test
	public void testOCSPWithoutNonce() {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		ocspSource.setDataLoader(new OCSPDataLoader());
		OCSPToken ocspToken = ocspSource.getOCSPToken(certificateToken, rootToken);
		assertNotNull(ocspToken);
	}

	@Test
	public void testOCSPWithNonce() {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		ocspSource.setDataLoader(new OCSPDataLoader());
		ocspSource.setNonceSource(new SecureRandomNonceSource());
		OCSPToken ocspToken = ocspSource.getOCSPToken(certificateToken, rootToken);
		assertNotNull(ocspToken);
	}

}
