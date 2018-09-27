package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class CounterSignatureValidationTest {

	@Test
	public void test() {

		DSSDocument doc = new FileDocument("src/test/resources/validation/TEST_S1a_C1a_InTL_VALID.xml");

		SignedDocumentValidator sdv = SignedDocumentValidator.fromDocument(doc);
		sdv.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = sdv.validateDocument();

		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		int countSignatures = 0;
		int countCounterSignatures = 0;

		for (SignatureWrapper signatureWrapper : signatures) {
			if (signatureWrapper.isCounterSignature()) {
				countCounterSignatures++;
			} else {
				countSignatures++;
			}
			assertNotNull(signatureWrapper.getSignatureFilename());
		}
		assertEquals(1, countSignatures);
		assertEquals(1, countCounterSignatures);
	}

}
