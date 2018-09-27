package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.List;
import java.util.Set;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class DSS1420 {

	@Test
	public void testSHA3_0() {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-1420/PAdES-BpB-att-SHA256-SHA3_256withRSA.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		PAdESSignature pades = (PAdESSignature) signatures.get(0);

		Set<DigestAlgorithm> messageDigestAlgorithms = pades.getMessageDigestAlgorithms();
		assertEquals(1, signatures.size());
		assertEquals(DigestAlgorithm.SHA256, messageDigestAlgorithms.iterator().next());
		assertNotNull(pades.getMessageDigestValue());

		assertEquals(EncryptionAlgorithm.RSA, pades.getEncryptionAlgorithm());
		assertEquals(DigestAlgorithm.SHA3_256, pades.getDigestAlgorithm());
		assertNull(pades.getMaskGenerationFunction());

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testSHA3_1() {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-1420/PAdES-BpB-att-SHA256-SHA3_224withRSA.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		PAdESSignature pades = (PAdESSignature) signatures.get(0);

		Set<DigestAlgorithm> messageDigestAlgorithms = pades.getMessageDigestAlgorithms();
		assertEquals(1, signatures.size());
		assertEquals(DigestAlgorithm.SHA256, messageDigestAlgorithms.iterator().next());
		assertNotNull(pades.getMessageDigestValue());

		assertEquals(EncryptionAlgorithm.RSA, pades.getEncryptionAlgorithm());
		assertEquals(DigestAlgorithm.SHA3_224, pades.getDigestAlgorithm());
		assertNull(pades.getMaskGenerationFunction());

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

}