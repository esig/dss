package eu.europa.esig.dss.x509.revocation.crl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;

import org.junit.Test;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.x509.revocation.crl.CRLToken;

public class CRLTokenTest {

	@Test
	public void testOK() throws IOException {
		FileDocument doc = new FileDocument("src/test/resources/crl/belgium2.crl");
		FileDocument caCert = new FileDocument("src/test/resources/belgiumrs2.crt");
		FileDocument tsaCert = new FileDocument("src/test/resources/TSA_BE.cer");

		try (InputStream crlStream = doc.openStream()) {
			CRLValidity crlValidity = CRLUtils.isValidCRL(crlStream, DSSUtils.loadCertificate(caCert.openStream()));
			assertNotNull(crlValidity);
			assertTrue(crlValidity.isSignatureIntact());
			assertTrue(crlValidity.isCrlSignKeyUsage());
			assertTrue(crlValidity.isIssuerX509PrincipalMatches());

			CRLToken crl = new CRLToken(DSSUtils.loadCertificate(tsaCert.openStream()), crlValidity);
			assertNotNull(crl);
			assertNotNull(crl.getAbbreviation());
			assertNotNull(crl.getCreationDate());
			assertNotNull(crl.getCrlValidity());
			assertNotNull(crl.getDSSId());
			assertNotNull(crl.getIssuerX500Principal());
			assertNotNull(crl.getPublicKeyOfTheSigner());
			assertNotNull(crl.getOrigin());
			assertNotNull(crl.toString());

			assertEquals(crlValidity.getExpiredCertsOnCRL(), crl.getExpiredCertsOnCRL());

			assertFalse(crl.isCertHashPresent());
			assertNull(crl.getArchiveCutOff());
		}
	}

	@Test(expected = DSSException.class)
	public void wrongCRLIssuer() throws IOException {
		FileDocument doc = new FileDocument("src/test/resources/crl/belgium2.crl");
		FileDocument tsaCert = new FileDocument("src/test/resources/TSA_BE.cer");

		try (InputStream crlStream = doc.openStream()) {
			CRLValidity crlValidity = CRLUtils.isValidCRL(crlStream, DSSUtils.loadCertificate(tsaCert.openStream()));
			assertNotNull(crlValidity);
			assertFalse(crlValidity.isSignatureIntact());
			assertFalse(crlValidity.isCrlSignKeyUsage());
			assertFalse(crlValidity.isIssuerX509PrincipalMatches());

			new CRLToken(DSSUtils.loadCertificate(tsaCert.openStream()), crlValidity);

		}
	}

	@Test(expected = DSSException.class)
	public void wrongCertIssuer() throws IOException {
		FileDocument doc = new FileDocument("src/test/resources/crl/belgium2.crl");
		FileDocument caCert = new FileDocument("src/test/resources/belgiumrs2.crt");

		try (InputStream crlStream = doc.openStream()) {
			CRLValidity crlValidity = CRLUtils.isValidCRL(crlStream, DSSUtils.loadCertificate(caCert.openStream()));
			assertNotNull(crlValidity);
			assertTrue(crlValidity.isSignatureIntact());
			assertTrue(crlValidity.isCrlSignKeyUsage());
			assertTrue(crlValidity.isIssuerX509PrincipalMatches());

			new CRLToken(DSSUtils.loadCertificate(caCert.openStream()), crlValidity);
		}
	}

}
