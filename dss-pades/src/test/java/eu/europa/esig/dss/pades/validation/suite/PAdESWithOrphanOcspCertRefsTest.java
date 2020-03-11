package eu.europa.esig.dss.pades.validation.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;

public class PAdESWithOrphanOcspCertRefsTest {
	
	@Test
	public void test() {
		
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/pades_with_orphan_ocsp_cert_refs.pdf"));

		PDFDocumentValidator validator = new PDFDocumentValidator(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
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

}
