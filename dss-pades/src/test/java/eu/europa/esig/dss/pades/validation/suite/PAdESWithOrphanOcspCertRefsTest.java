package eu.europa.esig.dss.pades.validation.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

public class PAdESWithOrphanOcspCertRefsTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/pades_with_orphan_ocsp_cert_refs.pdf"));
	}
	
	@Override
	protected void checkRevocationData(DiagnosticData diagnosticData) {
		Set<RevocationWrapper> allRevocationData = diagnosticData.getAllRevocationData();
		assertEquals(1, allRevocationData.size());
		
		RevocationWrapper revocationWrapper = allRevocationData.iterator().next();
		assertEquals(RevocationType.OCSP, revocationWrapper.getRevocationType());
		assertNotNull(revocationWrapper.foundCertificates());
		assertEquals(0, revocationWrapper.foundCertificates().getRelatedCertificates().size());
		assertEquals(1, revocationWrapper.foundCertificates().getOrphanCertificates().size());
		assertEquals(0, revocationWrapper.foundCertificates().getRelatedCertificateRefs().size());
		assertEquals(1, revocationWrapper.foundCertificates().getOrphanCertificateRefs().size());
		
		assertEquals(1, revocationWrapper.foundCertificates().getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
		
		assertNull(revocationWrapper.getSigningCertificate());
		assertTrue(Utils.isCollectionEmpty(revocationWrapper.getCertificateChain()));

		assertEquals(0, diagnosticData.getAllOrphanCertificateObjects().size());
		assertEquals(1, diagnosticData.getAllOrphanCertificateReferences().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationObjects().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationReferences().size());
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(0, diagnosticData.getAllOrphanCertificateObjects().size());
		assertEquals(1, diagnosticData.getAllOrphanCertificateReferences().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationObjects().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationReferences().size());
	}

}
