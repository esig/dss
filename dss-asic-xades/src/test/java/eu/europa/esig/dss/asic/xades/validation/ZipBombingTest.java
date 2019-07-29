package eu.europa.esig.dss.asic.xades.validation;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class ZipBombingTest {

	@Test
	public void zipBombing() {
		FileDocument doc = new FileDocument("src/test/resources/validation/zip-bomb.asice");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
	}

	@Test
	public void zipBombingPackageZip() {
		FileDocument doc = new FileDocument("src/test/resources/validation/zip-bomb-package-zip.asics");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
	}
	
	@Test(expected = DSSException.class)
	public void zipBombingOneLevelAsice() {
		FileDocument doc = new FileDocument("src/test/resources/validation/one-level-zip-bombing.asice");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		validator.validateDocument();
	}

	@Test(expected = DSSException.class)
	public void zipBombingOneLevelAsics() {
		FileDocument doc = new FileDocument("src/test/resources/validation/zip-bomb-package-zip-1gb.asics");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		validator.validateDocument();
	}
	
	@Test(expected = DSSException.class)
	public void zipBombingTooManyFilesAsice() {
		FileDocument doc = new FileDocument("src/test/resources/validation/container-too-many-files.asice");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		validator.validateDocument();
	}
	
	@Test
	public void zipBombingTooManyFilesAsics() {
		FileDocument doc = new FileDocument("src/test/resources/validation/container-too-many-files.asics");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
	}

}
