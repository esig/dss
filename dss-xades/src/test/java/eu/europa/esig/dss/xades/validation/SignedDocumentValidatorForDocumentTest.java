package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;

public class SignedDocumentValidatorForDocumentTest {

	@Test
	public void testXmlUTF8(){
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(new FileDocument(new File("src/test/resources/sample.xml")));
		assertTrue(documentValidator instanceof XMLDocumentValidator);
	}

	@Test
	public void testXmlUTF8InMemory() throws IOException {
		FileInputStream fis = new FileInputStream(new File("src/test/resources/sample.xml"));
		byte[] byteArray = IOUtils.toByteArray(fis);
		IOUtils.closeQuietly(fis);
		DSSDocument document = new InMemoryDocument(byteArray);
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(document);
		assertTrue(documentValidator instanceof XMLDocumentValidator);
	}

	@Test
	public void testXmlISO(){
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(new FileDocument(new File("src/test/resources/sampleISO.xml")));
		assertTrue(documentValidator instanceof XMLDocumentValidator);
	}

	@Test
	public void testXmlUISOInMemory() throws IOException {
		FileInputStream fis = new FileInputStream(new File("src/test/resources/sampleISO.xml"));
		byte[] byteArray = IOUtils.toByteArray(fis);
		IOUtils.closeQuietly(fis);
		DSSDocument document = new InMemoryDocument(byteArray);
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(document);
		assertTrue(documentValidator instanceof XMLDocumentValidator);
	}
}
