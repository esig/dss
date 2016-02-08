package eu.europa.esig.dss.xades.validation;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class DSS817Test {

	@Test
	public void test()  {
		DSSDocument doc = new FileDocument("src/test/resources/dss-817-test.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		validator.validateDocument();
	}
	
}
