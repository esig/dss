package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1636Test {
	
	@Test(expected = DSSException.class)
	public void dss1636WithContentTimestampTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1636/detached_cts.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
	}
	
	@Test
	public void dss1636WithoutContentTimestampTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1636/detached_no_cts.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
	}

}
