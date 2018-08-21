package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class DSS1376GetOriginalDocTest {

	private static final Logger LOG = LoggerFactory.getLogger(DSS1376GetOriginalDocTest.class);

	@BeforeClass
	public static void listing() {
		File folder = new File("src/test/resources/validation/dss-1376");
		File[] files = folder.listFiles();
		for (File file : files) {
			DSSDocument doc = new FileDocument(file);
			LOG.info("{} : {}", doc.getName(), doc.getDigest(DigestAlgorithm.SHA256));
		}
	}

	@Test
	public void getTestOriginSig() throws IOException {
		SignedDocumentValidator sdv = SignedDocumentValidator.fromDocument(new FileDocument("src/test/resources/validation/dss-1376/DSS1376-rev_n.pdf"));
		sdv.setCertificateVerifier(new CommonCertificateVerifier());
		List<AdvancedSignature> signatures = sdv.getSignatures();
		assertEquals(2, signatures.size());

		AdvancedSignature firstSig = signatures.get(1);

		DSSDocument expectedDoc = new FileDocument("src/test/resources/validation/dss-1376/DSS1376-rev_n-1.pdf");
		List<DSSDocument> originalDocuments = sdv.getOriginalDocuments(firstSig.getId());
		assertEquals(1, originalDocuments.size());
		DSSDocument retrievedDoc = originalDocuments.get(0);
		LOG.info("{} : {}", retrievedDoc.getName(), retrievedDoc.getDigest(DigestAlgorithm.SHA256));
		assertEquals(expectedDoc.getDigest(DigestAlgorithm.SHA256), retrievedDoc.getDigest(DigestAlgorithm.SHA256));

		AdvancedSignature secondSig = signatures.get(0);

		originalDocuments = sdv.getOriginalDocuments(secondSig.getId());
		assertEquals(1, originalDocuments.size());
		retrievedDoc = originalDocuments.get(0);

		// Signature has been generated in the very first version of the PDF
		byte[] byteArray = DSSUtils.toByteArray(retrievedDoc);
		assertTrue(byteArray.length == 0);
	}

}
