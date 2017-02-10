package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class DSS951Test {

	@Test
	public void testFile1() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-951/NexU-CAdES-B-B-Detached-Sha512.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isAttributePresent());
		assertTrue(signature.isDigestValuePresent());
		assertTrue(signature.isDigestValueMatch());
		assertTrue(signature.isIssuerSerialMatch());

		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

}
