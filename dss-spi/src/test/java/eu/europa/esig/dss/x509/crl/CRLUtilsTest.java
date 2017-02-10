package eu.europa.esig.dss.x509.crl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.X509CRL;

import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;

public class CRLUtilsTest {

	@Test
	public void isValidCRL() throws Exception {
		FileInputStream fis = new FileInputStream(new File("src/test/resources/crl/belgium2.crl"));
		X509CRL x509CRL = DSSUtils.loadCRL(fis);
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/belgiumrs2.crt"));
		CRLValidity validCRL = CRLUtils.isValidCRL(x509CRL, certificate);
		assertNotNull(validCRL);
		assertNotNull(validCRL.getSignatureAlgorithm());
		assertNotNull(validCRL.getThisUpdate());
		assertNotNull(validCRL.getNextUpdate());
		assertTrue(validCRL.isIssuerX509PrincipalMatches());
		assertFalse(validCRL.isUnknownCriticalExtension());
		assertTrue(validCRL.isSignatureIntact());
		assertTrue(validCRL.isCrlSignKeyUsage());
		assertTrue(validCRL.isValid());
		assertEquals(certificate, validCRL.getIssuerToken());
		assertEquals(x509CRL, validCRL.getX509CRL());
		assertTrue(Utils.isStringEmpty(validCRL.getSignatureInvalidityReason()));
		Utils.closeQuietly(fis);
	}

	@Test
	public void isValidCRLWrongCertificate() throws Exception {
		FileInputStream fis = new FileInputStream(new File("src/test/resources/crl/belgium2.crl"));
		X509CRL x509CRL = DSSUtils.loadCRL(fis);
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));
		CRLValidity validCRL = CRLUtils.isValidCRL(x509CRL, certificate);
		assertNotNull(validCRL);
		assertFalse(validCRL.isIssuerX509PrincipalMatches());
		assertFalse(validCRL.isSignatureIntact());
		assertFalse(validCRL.isValid());
		assertFalse(Utils.isStringEmpty(validCRL.getSignatureInvalidityReason()));
		Utils.closeQuietly(fis);
	}

	@Test
	public void hasCRLSignKeyUsage() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));
		assertTrue(CRLUtils.hasCRLSignKeyUsage(certificate));

		certificate = DSSUtils.loadCertificate(new File("src/test/resources/TSP_Certificate_2014.crt"));
		assertFalse(CRLUtils.hasCRLSignKeyUsage(certificate));
	}

	@Test
	public void getExpiredCertsOnCRL() throws Exception {
		X509CRL x509crl = DSSUtils.loadCRL(new FileInputStream("src/test/resources/crl/crl_with_expiredCertsOnCRL_extension.crl"));
		assertNotNull(CRLUtils.getExpiredCertsOnCRL(x509crl));

		x509crl = DSSUtils.loadCRL(new FileInputStream("src/test/resources/crl/LTRCA.crl"));
		assertNull(CRLUtils.getExpiredCertsOnCRL(x509crl));
	}

}
