package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class DSS1524Test {

	@Test
	public void testWithWrongAttachment() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/sig_bundle.signed_detached.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setDetachedContents(Arrays.<DSSDocument>asList(new InMemoryDocument(new byte[] { 1, 2, 3 })));
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
	}

	@Test
	public void testWithAttachment() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/sig_bundle.signed_detached.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);

		DigestDocument digestDoc = new DigestDocument();
		digestDoc.addDigest(DigestAlgorithm.SHA512, "kSi69weRFM3ehJVf/RZ6ASMoHUuY2g0toUYNFr68FU3nS5fT48NZK4W4Ks33zDOo+0GzIbOFMa7GRQ1r0gCXzg==");
		validator.setDetachedContents(Arrays.<DSSDocument>asList(digestDoc));
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

		assertTrue(signatureWrapper.isSignatureIntact());
		assertTrue(signatureWrapper.isBLevelTechnicallyValid());

		// Unable to validate archive timestamp with a digest document
		assertFalse(signatureWrapper.isALevelTechnicallyValid());
	}
	
	@Test
	public void testNoAttachment() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/sig_bundle.signed_detached.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		reports.print();
	}

}
