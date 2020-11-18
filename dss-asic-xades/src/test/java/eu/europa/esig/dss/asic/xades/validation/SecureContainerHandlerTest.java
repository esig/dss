package eu.europa.esig.dss.asic.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.asic.common.SecureContainerHandler;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class SecureContainerHandlerTest extends PKIFactoryAccess {

	private static DSSDocument smallerDocument;
	private static DSSDocument biggerDocument;

	@BeforeAll
	public static void init() {
		smallerDocument = new FileDocument("src/test/resources/validation/dss-2245-2400.asice");
		biggerDocument = new FileDocument("src/test/resources/validation/dss-2245-2500.asice");
	}

	@Test
	public void testDefault() {
		ZipUtils.getInstance().setZipContainerHandler(new SecureContainerHandler());

		DocumentValidator validator = getValidator(smallerDocument);
		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		validator = getValidator(biggerDocument);
		reports = validator.validateDocument();
		assertNotNull(reports);
	}

	@Test
	public void testSmallerRatio() {
		SecureContainerHandler secureContainerHandler = new SecureContainerHandler();
		secureContainerHandler.setMaxCompressionRatio(50);
		ZipUtils.getInstance().setZipContainerHandler(secureContainerHandler);

		DocumentValidator validator = getValidator(smallerDocument);
		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		Exception exception = assertThrows(DSSException.class, () -> getValidator(biggerDocument));
		assertEquals("Zip Bomb detected in the ZIP container. Validation is interrupted.", exception.getMessage());
	}

	@Test
	public void testBiggerThreshold() {
		SecureContainerHandler secureContainerHandler = new SecureContainerHandler();
		secureContainerHandler.setMaxCompressionRatio(50);
		ZipUtils.getInstance().setZipContainerHandler(secureContainerHandler);

		Exception exception = assertThrows(DSSException.class, () -> getValidator(biggerDocument));
		assertEquals("Zip Bomb detected in the ZIP container. Validation is interrupted.", exception.getMessage());

		secureContainerHandler.setThreshold(100000000);

		DocumentValidator validator = getValidator(biggerDocument);
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
	}

	@Test
	public void testDifferentDocumentsAmount() {
		SecureContainerHandler secureContainerHandler = new SecureContainerHandler();
		secureContainerHandler.setMaxAllowedFilesAmount(1);
		ZipUtils.getInstance().setZipContainerHandler(secureContainerHandler);

		Exception exception = assertThrows(DSSException.class, () -> getValidator(smallerDocument));
		assertEquals("Too many files detected. Cannot extract ASiC content from the file.", exception.getMessage());
	}

	private DocumentValidator getValidator(DSSDocument documentToValidate) {
		ASiCContainerWithXAdESValidator validator = new ASiCContainerWithXAdESValidator(documentToValidate);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		return validator;
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
