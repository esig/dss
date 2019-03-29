package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.XmlCertificateSourceType;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class XMLCertificateWrappingTest extends PKIFactoryAccess {
	
	@Test
	public void certificateSourcesTest() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/HU_POL/Signature-X-HU_POL-3.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<CertificateWrapper> certificates = diagnosticData.getUsedCertificates();
		for (CertificateWrapper certificate : certificates) {
			assertNotNull(certificate.getSources());
			assertNotEquals(0, certificate.getSources().size());
			assertFalse(certificate.getSources().contains(XmlCertificateSourceType.UNKNOWN));
		}
	}
	
	@Test
	public void certificateMultipleSourcesTest() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/CZ_SEF/Signature-X-CZ_SEF-5.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<CertificateWrapper> certificates = diagnosticData.getUsedCertificates();
		int certsFromTimestamp = 0;
		for (CertificateWrapper certificate : certificates) {
			List<XmlCertificateSourceType> certSources = certificate.getSources();
			assertNotNull(certSources);
			assertNotEquals(0, certSources.size());
			if (certSources.contains(XmlCertificateSourceType.TIMESTAMP)) {
				assertEquals(2, certSources.size());
				assertTrue(certSources.contains(XmlCertificateSourceType.SIGNATURE));
				certsFromTimestamp++;
			}
			assertFalse(certificate.getSources().contains(XmlCertificateSourceType.UNKNOWN));
		}
		assertEquals(1, certsFromTimestamp);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
