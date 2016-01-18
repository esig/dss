package eu.europa.esig.dss.asic.validation;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.EN319102.report.Reports;

public class ASiCEWith2SignaturesTest {
	
	@Test
	public void test() {
		DSSDocument asicContainer = new FileDocument("src/test/resources/ASiCEWith2Signatures.bdoc");
		
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(asicContainer);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		Assert.assertNotNull(reports);
		reports.print();
		reports = reports.getNextReports();
		Assert.assertNotNull(reports);
		reports.print();
	}
}
