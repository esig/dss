package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class DetectionModificationAfterSignTest {

	@Test
	public void testWithModification() throws IOException {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/modified_after_signature.pdf");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());

		AdvancedSignature advancedSignature = signatures.get(0);

		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(advancedSignature.getId());
		assertEquals(1, originalDocuments.size());

		DSSDocument expected = new FileDocument("src/test/resources/validation/retrieved-modified_after_signature.pdf");
		assertEquals(expected.getDigest(DigestAlgorithm.SHA256), originalDocuments.get(0).getDigest(DigestAlgorithm.SHA256));
	}

}
