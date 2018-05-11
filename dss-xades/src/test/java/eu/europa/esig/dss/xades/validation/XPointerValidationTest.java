package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class XPointerValidationTest {

	@Test
	public void test() {
		SignedDocumentValidator sdv = SignedDocumentValidator.fromDocument(new FileDocument("src/test/resources/validation/10963_signed.xml"));
		sdv.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = sdv.validateDocument();
		// reports.print();
		assertNotNull(reports);
	}

}
