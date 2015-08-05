package eu.europa.esig.dss.asic.validation;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.dss.validation.report.Reports;

public class ASiCWithModifiedCertValuesTest {

	/* File contains empty tags or blank lines for level LT */
	@Test
	public void test() {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument("src/test/resources/validation/Signature-ASiC_LT_modified_cert_values.asice"));
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(SignatureLevel.XAdES_BASELINE_T.name(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

}
