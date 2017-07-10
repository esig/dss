package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.Test;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class CMSDocumentValidatorTest {

	private static final String PATH = "src/test/resources/validation/dss-768/FD1&FD2&FEA.pdf.p7m";

	@Test
	public void testCMSOnly() throws IOException, CMSException {
		CMSSignedData cmsSignedData = new CMSSignedData(new FileInputStream(PATH));
		CMSDocumentValidator validator = new CMSDocumentValidator(cmsSignedData);
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertTrue(Utils.isCollectionNotEmpty(signatures));
	}

	@Test
	public void testFileDocument() {
		CMSDocumentValidator validator = new CMSDocumentValidator(new FileDocument(PATH));
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertTrue(Utils.isCollectionNotEmpty(signatures));
	}

	@Test
	public void testInMemoryDocument() throws FileNotFoundException {
		CMSDocumentValidator validator = new CMSDocumentValidator(new InMemoryDocument(new FileInputStream(PATH)));
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertTrue(Utils.isCollectionNotEmpty(signatures));
	}

}
