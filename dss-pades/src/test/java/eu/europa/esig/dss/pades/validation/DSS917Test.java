package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class DSS917Test {

	@Test
	public void test() throws Exception {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/hello_signed_INCSAVE_signed_EDITED.pdf")));
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignatureWrapper> allSignatures = diagnosticData.getSignatures();
		assertEquals(2, allSignatures.size());

		assertTrue(allSignatures.get(0).isBLevelTechnicallyValid());
		assertFalse(allSignatures.get(1).isBLevelTechnicallyValid());
	}

	@Test
	public void testCorrect() throws Exception {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/hello_signed_INCSAVE_signed.pdf")));
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignatureWrapper> allSignatures = diagnosticData.getSignatures();
		assertEquals(2, allSignatures.size());

		assertTrue(allSignatures.get(0).isBLevelTechnicallyValid());
		assertTrue(allSignatures.get(1).isBLevelTechnicallyValid());
	}

}
