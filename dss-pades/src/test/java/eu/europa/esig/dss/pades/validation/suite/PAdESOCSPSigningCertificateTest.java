package eu.europa.esig.dss.pades.validation.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

public class PAdESOCSPSigningCertificateTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/pades-ocsp-sign-cert.pdf"));
	}
	
	@Override
	protected void checkRevocationData(DiagnosticData diagnosticData) {
		super.checkRevocationData(diagnosticData);
		
		for (RevocationWrapper revocationWrapper : diagnosticData.getAllRevocationData()) {
			assertNotNull(revocationWrapper.getSigningCertificate());
			
			List<RelatedCertificateWrapper> relatedCertificates = revocationWrapper.foundCertificates().getRelatedCertificates();
			assertEquals(1, relatedCertificates.size());
			assertEquals(0, revocationWrapper.foundCertificates().getOrphanCertificates().size());
			
			RelatedCertificateWrapper relatedCertificateWrapper = relatedCertificates.get(0);
			assertEquals(1, relatedCertificateWrapper.getReferences().size());
			
			CertificateRefWrapper certificateRefWrapper = relatedCertificateWrapper.getReferences().get(0);
			assertEquals(CertificateRefOrigin.SIGNING_CERTIFICATE, certificateRefWrapper.getOrigin());
		}
	}

}
