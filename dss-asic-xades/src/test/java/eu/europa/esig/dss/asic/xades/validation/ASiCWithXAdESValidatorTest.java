package eu.europa.esig.dss.asic.xades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class ASiCWithXAdESValidatorTest {
	
	@Test
	public void asiceTest() {
		ASiCContainerWithXAdESValidator validator = new ASiCContainerWithXAdESValidator(
				new FileDocument("src/test/resources/validation/onefile-ok.asice"));
		validate(validator, 1);
	}
	
	@Test
	public void asiceMultiFileTest() {
		ASiCContainerWithXAdESValidator validator = new ASiCContainerWithXAdESValidator(
				new FileDocument("src/test/resources/validation/multifiles-ok.asice"));
		validate(validator, 2);
	}
	
	@Test
	public void asicsTest() {
		ASiCContainerWithXAdESValidator validator = new ASiCContainerWithXAdESValidator(
				new FileDocument("src/test/resources/validation/onefile-ok.asics"));
		validate(validator, 1);
	}
	
	@Test
	public void asicsMultiFileTest() {
		ASiCContainerWithXAdESValidator validator = new ASiCContainerWithXAdESValidator(
				new FileDocument("src/test/resources/validation/multifiles-ok.asics"));
		validate(validator, 2);
	}
	
	@Test(expected = DSSException.class)
	public void binaryFileValidation() {
		ASiCContainerWithXAdESValidator validator = new ASiCContainerWithXAdESValidator(
				new InMemoryDocument(new byte[] {'1', '2', '3'}));
		validate(validator, 0);
	}
	
	@Test(expected = DSSException.class)
	public void malformedArchiveValidation() {
		ASiCContainerWithXAdESValidator validator = new ASiCContainerWithXAdESValidator(
				new FileDocument("src/test/resources/validation/malformed-container.asice"));
		validate(validator, 1);
	}
	
	@Test(expected = NullPointerException.class)
	public void emptyValidatorTest() {
		ASiCContainerWithXAdESValidator validator = new ASiCContainerWithXAdESValidator();
		validate(validator, 0);
	}

	@Test
	public void isSupportedBinaryFileTest() {
		ASiCContainerWithXAdESValidator validator = new ASiCContainerWithXAdESValidator();
		assertFalse(validator.isSupported(new InMemoryDocument(new byte[] {'1', '2', '3'})));
	}

	@Test
	public void isSupportedMalformedContainerTest() {
		ASiCContainerWithXAdESValidator validator = new ASiCContainerWithXAdESValidator();
		assertFalse(validator.isSupported(new FileDocument("src/test/resources/validation/malformed-container.asice")));
	}

	@Test(expected = DSSException.class)
	public void validateBinaryFileFromDocumentTest() {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new InMemoryDocument(new byte[] {'1', '2', '3'}));
		validate(validator, 0);
	}

	@Test(expected = DSSException.class)
	public void validateMalformedContainerFromDocumentTest() {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(
				new FileDocument("src/test/resources/validation/malformed-container.asice"));
		validate(validator, 1);
	}
	
	private void validate(SignedDocumentValidator validator, int signatures) {
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		SimpleReport simpleReport = reports.getSimpleReport();
		assertNotNull(simpleReport);
		assertEquals(signatures, simpleReport.getSignaturesCount());
	}

}
