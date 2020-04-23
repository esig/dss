package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignatureCertificateSource;

public class CAdESDuplicateCertRefsTest extends AbstractCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/Signature-C-B-LTA-10.p7m");
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		AdvancedSignature advancedSignature = advancedSignatures.get(0);
		SignatureCertificateSource certificateSource = advancedSignature.getCertificateSource();
		assertEquals(4, certificateSource.getSigningCertificateRefs().size());
		assertEquals(3, certificateSource.getCompleteCertificateRefs().size());
		
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();
		assertEquals(4, foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
		assertEquals(3, foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size());
		
		int doubleRefCounter = 0;
		for (RelatedCertificateWrapper relatedCertificateWrapper : foundCertificates.getRelatedCertificates()) {
			if (relatedCertificateWrapper.getReferences().size() > 1) {
				++doubleRefCounter;
			}
		}
		assertEquals(3, doubleRefCounter);
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureWrapper.isSigningCertificateReferencePresent());
		assertFalse(signatureWrapper.isSigningCertificateReferenceUnique());
		assertNotNull(signatureWrapper.getSigningCertificateReference());
	}

}
