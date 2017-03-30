package eu.europa.esig.dss.asic.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class ASiCEWithZipCommentTest {

	@Test
	public void test() {
		DSSDocument asicContainer = new FileDocument("src/test/resources/validation/test-zip-comment.asice");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(asicContainer);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertEquals(1, diagnosticData.getSignatureIdList().size());
		assertEquals(
				"LIB DigiDoc4j/DEV format: application/vnd.etsi.asic-e+zip signatureProfile: ASiC_E_BASELINE_LT Java: 1.8.0_111/Oracle Corporation OS: Linux/amd64/3.10.0-514.el7.x86_64 JVM: OpenJDK 64-Bit Server VM/Oracle Corporation/25.111-b15",
				diagnosticData.getZipComment());
	}

}
