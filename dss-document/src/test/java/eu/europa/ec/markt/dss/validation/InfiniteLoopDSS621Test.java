package eu.europa.ec.markt.dss.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.junit.Test;

import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;

public class InfiniteLoopDSS621Test {

	@Test(timeout = 5000)
	public void testReadTimestamp1() throws Exception {
		DSSDocument signDocument = new FileDocument(new File("src/test/resources/validation/pades-5-signatures-and-1-document-timestamp.pdf"));
		final CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();

		final SignedDocumentValidator signedDocumentValidator = SignedDocumentValidator.fromDocument(signDocument);
		signedDocumentValidator.setCertificateVerifier(certificateVerifier);

		final List<AdvancedSignature> signatures = signedDocumentValidator.getSignatures();

		assertEquals(5, signatures.size());
		for (final AdvancedSignature signature : signatures) {
			assertTrue(signature.checkSignatureIntegrity().isSignatureIntact());
			assertTrue(CollectionUtils.isNotEmpty(signature.getSignatureTimestamps()));
		}
	}

}
