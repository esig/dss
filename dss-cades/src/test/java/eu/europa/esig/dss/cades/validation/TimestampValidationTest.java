package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.DetachedTimestampValidator;

public class TimestampValidationTest {

	@Test
	public void test() {
		DSSDocument document = new FileDocument("src/test/resources/validation/d-trust.tsr");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		assertTrue(validator instanceof DetachedTimestampValidator);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
	}

	private CertificateVerifier getOfflineCertificateVerifier() {
		CertificateVerifier cv = new CommonCertificateVerifier();
		cv.setDataLoader(new IgnoreDataLoader());
		return cv;
	}

}
