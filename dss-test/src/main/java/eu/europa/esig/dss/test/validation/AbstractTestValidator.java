package eu.europa.esig.dss.test.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public abstract class AbstractTestValidator {
	
	protected abstract SignedDocumentValidator initEmptyValidator();
	
	protected abstract SignedDocumentValidator initValidator(DSSDocument document);
	
	protected abstract List<DSSDocument> getValidDocuments();
	
	protected abstract DSSDocument getMalformedDocument();
	
	protected abstract DSSDocument getOtherTypeDocument();
	
	protected abstract DSSDocument getNoSignatureDocument();
	
	protected DSSDocument getBinaryDocument() {
		return new InMemoryDocument(new byte[] {'1', '2', '3'});
	}
	
	@Test
	public void validateSignatures() {
		List<DSSDocument> documents = getValidDocuments();
		for (DSSDocument document : documents) {
			SignedDocumentValidator validator = initValidator(document);
			validate(validator, true);
		}
	}
	
	@Test
	public void validateFromDocument() {
		List<DSSDocument> documents = getValidDocuments();
		for (DSSDocument document : documents) {
			SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
			validate(validator, true);
		}
	}
	
	@Test(expected = DSSException.class)
	public void binaryDocumentValidation() {
		SignedDocumentValidator validator = initValidator(getBinaryDocument());
		validate(validator);
	}
	
	@Test(expected = DSSException.class)
	public void malformedDocumentValidation() {
		SignedDocumentValidator validator = initValidator(getMalformedDocument());
		validate(validator);
	}

	@Test(expected = DSSException.class)
	public void otherDocumentTypeValidation() {
		SignedDocumentValidator validator = initValidator(getOtherTypeDocument());
		validate(validator);
	}
	
	@Test
	public void validateNoSignatureDocument() {
		DSSDocument document = getNoSignatureDocument();
		if (document != null) {
			SignedDocumentValidator validator = initValidator(document);
			validate(validator, false);
		}
	}
	
	@Test
	public void isSupportedValidDocument() {
		List<DSSDocument> documents = getValidDocuments();
		for (DSSDocument document : documents) {
			assertTrue(initEmptyValidator().isSupported(document));
		}
	}
	
	@Test
	public void isSupportedBinaryDocument() {
		assertFalse(initEmptyValidator().isSupported(getBinaryDocument()));
	}
	
	@Test
	public void isSupportedMalformedDocument() {
		assertFalse(initEmptyValidator().isSupported(getMalformedDocument()));
	}
	
	@Test
	public void isSupportedOtherTypeDocument() {
		assertFalse(initEmptyValidator().isSupported(getOtherTypeDocument()));
	}
	
	@Test
	public void isSupportedNoSignatureDocument() {
		DSSDocument document = getNoSignatureDocument();
		if (document != null) {
			assertTrue(initEmptyValidator().isSupported(document));
		}
	}
	
	@Test(expected = NullPointerException.class)
	public void nullDocumentProvided() {
		SignedDocumentValidator validator = initValidator(null);
		validate(validator);
	}
	
	@Test(expected = NullPointerException.class)
	public void nullFromDocument() {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(null);
		validate(validator);
	}
	
	protected void validate(SignedDocumentValidator validator) {
		validate(validator, false);
	}
	
	protected void validate(SignedDocumentValidator validator, boolean containsSignature) {
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		SimpleReport simpleReport = reports.getSimpleReport();
		assertNotNull(simpleReport);
		assertEquals(containsSignature, simpleReport.getSignaturesCount() > 0);
	}

}
