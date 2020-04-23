package eu.europa.esig.dss.pades.validation.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.OrphanCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignatureCertificateSource;

public class DSS2025Test extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/DSS-2025.pdf"));
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isSigningCertificateIdentified());
		assertTrue(signature.isSigningCertificateReferencePresent());
		assertFalse(signature.isSigningCertificateReferenceUnique());
		
		CertificateRefWrapper signingCertificateReference = signature.getSigningCertificateReference();
		assertNotNull(signingCertificateReference);
		assertTrue(signingCertificateReference.isDigestValuePresent());
		assertTrue(signingCertificateReference.isDigestValueMatch());
		assertTrue(signingCertificateReference.isIssuerSerialPresent());
		assertTrue(signingCertificateReference.isIssuerSerialMatch());
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		AdvancedSignature advancedSignature = advancedSignatures.get(0);
		SignatureCertificateSource certificateSource = advancedSignature.getCertificateSource();
		
		List<CertificateRef> signingCertificateRefs = certificateSource.getSigningCertificateRefs();
		assertEquals(1, signingCertificateRefs.size());
		List<CertificateRefOrigin> signingCertificateRefOrigins = certificateSource.getCertificateRefOrigins(signingCertificateRefs.get(0));
		assertEquals(2, signingCertificateRefOrigins.size());
		
		SignatureWrapper signature = diagnosticData.getSignatureById(advancedSignature.getId());
		FoundCertificatesProxy foundCertificates = signature.foundCertificates();
		
		List<RelatedCertificateWrapper> relatedSignCertRefs = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
		assertEquals(2, relatedSignCertRefs.size());
		List<OrphanCertificateWrapper> orphanSignCertRefs = foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
		assertEquals(0,  orphanSignCertRefs.size());
		
		assertEquals(relatedSignCertRefs.get(0), relatedSignCertRefs.get(1));
	}

}
