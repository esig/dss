package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class XAdESWithOcspNoEmbeddedCertsTest extends PKIFactoryAccess {
	
	@Test
	public void test() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/xades-ocsp-not-embeds-certs.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		Set<RevocationWrapper> allRevocationData = diagnosticData.getAllRevocationData();
		assertEquals(2, allRevocationData.size());
		List<String> certIds = new ArrayList<>();
		for (RevocationWrapper revocationWrapper : diagnosticData.getAllRevocationData()) {
			assertEquals(RevocationType.OCSP, revocationWrapper.getRevocationType());
			assertNotNull(revocationWrapper.foundCertificates());
			assertEquals(1, revocationWrapper.foundCertificates().getRelatedCertificates().size());
			assertEquals(0, revocationWrapper.foundCertificates().getOrphanCertificates().size());
			assertEquals(1, revocationWrapper.foundCertificates().getRelatedCertificateRefs().size());
			assertEquals(0, revocationWrapper.foundCertificates().getOrphanCertificateRefs().size());
			
			List<RelatedCertificateWrapper> signingCerts = revocationWrapper.foundCertificates()
					.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
			assertEquals(1, signingCerts.size());
			RelatedCertificateWrapper signingCertificate = signingCerts.get(0);
			assertTrue(Utils.isCollectionEmpty(signingCertificate.getOrigins()));
			
			assertNotNull(revocationWrapper.getSigningCertificate());
			assertTrue(Utils.isCollectionNotEmpty(revocationWrapper.getCertificateChain()));
			assertEquals(signingCertificate.getId(), revocationWrapper.getSigningCertificate().getId());
			certIds.add(signingCertificate.getId());
		}
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<RelatedCertificateWrapper> relatedCertificates = signature.foundCertificates().getRelatedCertificates();
		List<String> foundCertIds = relatedCertificates.stream().map(RelatedCertificateWrapper::getId).collect(Collectors.toList());
		for (String id : certIds) {
			assertTrue(foundCertIds.contains(id));
		}
		
		assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanCertificateObjects()));
		assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanCertificateReferences()));
		assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanRevocationObjects()));
		assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanRevocationReferences()));
		
	}

	@Override
	protected String getSigningAlias() {
		// TODO Auto-generated method stub
		return null;
	}

}
