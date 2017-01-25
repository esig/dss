package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.pseudo.CertificateHasPseudoCondition;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class PseudoTest {

	@Test
	public void testNoPseudo() {
		XmlCertificate xmlCert = new XmlCertificate();
		noPseudo(xmlCert);
	}

	@Test
	public void testNoPseudoCN() {
		XmlCertificate xmlCert = new XmlCertificate();
		xmlCert.setCommonName("Test");
		noPseudo(xmlCert);
	}

	@Test
	public void testNoPseudoCNWithPNNotGermany() {
		XmlCertificate xmlCert = new XmlCertificate();
		xmlCert.setCommonName("Test:PN");
		xmlCert.setCountryName("BE");
		noPseudo(xmlCert);
	}

	@Test
	public void testNoPseudoCNWithPNGermany() {
		XmlCertificate xmlCert = new XmlCertificate();
		xmlCert.setCommonName("Test:PN");
		xmlCert.setCountryName("DE");
		hasPseudo(xmlCert);
	}

	@Test
	public void testPseudo() {
		XmlCertificate xmlCert = new XmlCertificate();
		xmlCert.setPseudonym("Test");
		hasPseudo(xmlCert);
	}

	private void noPseudo(XmlCertificate xmlCert) {
		CertificateWrapper certificate = new CertificateWrapper(xmlCert);
		CertificateHasPseudoCondition condition = new CertificateHasPseudoCondition(certificate);
		assertFalse(condition.check());
	}

	private void hasPseudo(XmlCertificate xmlCert) {
		CertificateWrapper certificate = new CertificateWrapper(xmlCert);
		CertificateHasPseudoCondition condition = new CertificateHasPseudoCondition(certificate);
		assertTrue(condition.check());
	}

}
