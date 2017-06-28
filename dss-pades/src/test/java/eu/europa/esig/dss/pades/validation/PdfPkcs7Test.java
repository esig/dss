package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;

import java.io.File;

import org.junit.Test;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class PdfPkcs7Test {

	@Test
	public void test() throws Exception {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(new File("src/test/resources/validation/pkcs7.pdf")));
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(SignatureLevel.PKCS7_T.toString(), signatureById.getSignatureFormat());

		// reports.print();
	}

}
