package eu.europa.esig.dss.asic.cades.validation;

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

public class ASiCWithCAdESValidatorTest {
	
	@Test
	public void asiceTest() {
		ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator(
				new FileDocument("src/test/resources/validation/onefile-ok.asice"));
		validate(validator, 1);
	}
	
	@Test
	public void asiceMultiFileTest() {
		ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator(
				new FileDocument("src/test/resources/validation/multifiles-ok.asice"));
		validate(validator, 1);
	}
	
	@Test
	public void asicsTest() {
		ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator(
				new FileDocument("src/test/resources/validation/onefile-ok.asics"));
		validate(validator, 1);
	}
	
	@Test
	public void asicsMultiFileTest() {
		ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator(
				new FileDocument("src/test/resources/validation/multifiles-ok.asics"));
		validate(validator, 1);
	}
	
	@Test(expected = DSSException.class)
	public void binaryFileValidation() {
		ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator(
				new InMemoryDocument(new byte[] {'1', '2', '3'}));
		validate(validator, 0);
	}
	
	@Test(expected = DSSException.class)
	public void malformedArchiveValidation() {
		ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator(
				new FileDocument("src/test/resources/validation/malformed-container.asics"));
		validate(validator, 1);
	}
	
	@Test(expected = NullPointerException.class)
	public void emptyValidatorTest() {
		ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator();
		validate(validator, 0);
	}

	@Test
	public void isSupportedBinaryFileTest() {
		ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator();
		assertFalse(validator.isSupported(new InMemoryDocument(new byte[] {'1', '2', '3'})));
	}

	@Test
	public void isSupportedMalformedContainerTest() {
		ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator();
		assertFalse(validator.isSupported(new FileDocument("src/test/resources/validation/malformed-container.asics")));
	}

	@Test(expected = DSSException.class)
	public void validateBinaryFileFromDocumentTest() {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new InMemoryDocument(new byte[] {'1', '2', '3'}));
		validate(validator, 0);
	}

	@Test(expected = DSSException.class)
	public void validateMalformedContainerFromDocumentTest() {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(
				new FileDocument("src/test/resources/validation/malformed-container.asics"));
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
