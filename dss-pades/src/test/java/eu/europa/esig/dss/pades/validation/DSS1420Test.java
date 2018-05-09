package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class DSS1420Test {

	@Test
	public void testSHA3() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1420/PAdES-BpB-att-SHA256-SHA3_256withRSA.pdf");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

}