package eu.europa.esig.dss.pades.validation.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.OrphanCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

public class PAdESWithDssVriAndCertRefTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/Signature-P-FR_CS-5.pdf"));
	}
	
	@Override
	protected void checkNoDuplicateCompleteCertificates(FoundCertificatesProxy foundCertificates) {
		super.checkNoDuplicateCompleteCertificates(foundCertificates);
		
		List<String> usedIds = new ArrayList<>();
		for (CertificateWrapper certificateWrapper : foundCertificates.getRelatedCertificates()) {
			assertFalse(usedIds.contains(certificateWrapper.getId()));
			usedIds.add(certificateWrapper.getId());
		}
		for (OrphanCertificateWrapper certificateWrapper : foundCertificates.getOrphanCertificates()) {
			assertFalse(usedIds.contains(certificateWrapper.getId()));
			usedIds.add(certificateWrapper.getId());
		}
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureWrapper.isDigestValuePresent());
		assertTrue(signatureWrapper.isDigestValueMatch());
		assertTrue(signatureWrapper.isIssuerSerialMatch());
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(0, diagnosticData.getAllOrphanCertificateObjects().size());
		assertEquals(0, diagnosticData.getAllOrphanCertificateReferences().size());
		assertEquals(2, diagnosticData.getAllOrphanRevocationObjects().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationReferences().size());
	}
	
}
