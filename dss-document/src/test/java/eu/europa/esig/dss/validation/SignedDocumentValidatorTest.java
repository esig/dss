package eu.europa.esig.dss.validation;

import org.junit.Test;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.FileDocument;

public class SignedDocumentValidatorTest {

	@Test(expected = DSSException.class)
	public void testNoDepencency() {
		SignedDocumentValidator.fromDocument(new FileDocument("src/test/resources/sample.xml"));
	}

}
