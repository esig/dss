package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.test.validation.AbstractTestValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class PDFDocumentValidatorCheck extends AbstractTestValidator {

	@Test
	public void isSupported() {
		PDFDocumentValidator validator = new PDFDocumentValidator();
		
		byte[] wrongBytes = new byte[] { 1, 2 };
		assertFalse(validator.isSupported(new InMemoryDocument(wrongBytes)));
		assertFalse(validator.isSupported(new InMemoryDocument(new byte[] { '<', '?', 'x', 'm', 'l' })));
		assertFalse(validator.isSupported(new InMemoryDocument(new byte[] { '%' })));
		assertFalse(validator.isSupported(new InMemoryDocument(new byte[] { 'P', 'D', 'F' })));
		
		assertTrue(validator.isSupported(new InMemoryDocument(new byte[] { '%', 'P', 'D', 'F', '-' })));
		assertTrue(validator.isSupported(new InMemoryDocument(new byte[] { '%', 'P', 'D', 'F', '-', '1', '.', '4' })));
	}

	@Override
	protected SignedDocumentValidator initEmptyValidator() {
		return new PDFDocumentValidator();
	}

	@Override
	protected SignedDocumentValidator initValidator(DSSDocument document) {
		return new PDFDocumentValidator(document);
	}

	@Override
	protected List<DSSDocument> getValidDocuments() {
		List<DSSDocument> documents = new ArrayList<DSSDocument>();
		documents.add(new InMemoryDocument(getClass().getResourceAsStream("/validation/pdf-signed-original.pdf")));
		documents.add(new InMemoryDocument(getClass().getResourceAsStream("/validation/PAdES-LTA.pdf")));
		documents.add(new InMemoryDocument(getClass().getResourceAsStream("/validation/encrypted.pdf")));
		return documents;
	}

	@Override
	protected DSSDocument getMalformedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/malformed-pades.pdf"));
	}

	@Override
	protected DSSDocument getOtherTypeDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"));
	}

	@Override
	protected DSSDocument getNoSignatureDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));
	}

}
