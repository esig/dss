package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocationRef;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class CAdESRevocationWrapperTest extends PKIFactoryAccess {
	
	@Test
	public void revocationValuesTest() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-CAdES/HU_POL/Signature-C-HU_POL-3.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports report = validator.validateDocument();
		// report.print();
		DiagnosticData diagnosticData = report.getDiagnosticData();
		int revocationSignatureOriginCounter = 0;
		Set<RevocationWrapper> revocationData = diagnosticData.getAllRevocationData();
		for (RevocationWrapper revocation : revocationData) {
			assertNotNull(revocation.getRevocationType());
			assertNotNull(revocation.getOrigin());
			if (RevocationOrigin.SIGNATURE.equals(revocation.getOrigin())) {
				revocationSignatureOriginCounter++;
			}
		}
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		assertEquals(2, revocationSignatureOriginCounter);
		assertEquals(0, signature.getRevocationIdsByType(RevocationType.CRL).size());
		assertEquals(2, signature.getRevocationIdsByType(RevocationType.OCSP).size());
		assertEquals(2, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(0, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
		assertEquals(0, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.DSS_DICTIONARY).size());
	}
	
	@Test
	public void revocationCRLRefsTest() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/cades/CAdES-A/Sample_Set_11/Signature-C-A-XL-1.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports report = validator.validateDocument();
		// report.print();
		DiagnosticData diagnosticData = report.getDiagnosticData();SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlRevocationRef> foundRevocationRefs = signature.getAllFoundRevocationRefs();
		assertNotNull(foundRevocationRefs);
		assertEquals(3, foundRevocationRefs.size());
		assertEquals(3, signature.getFoundRevocationRefsByOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
		assertEquals(0, signature.getFoundRevocationRefsByOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS).size());
		assertEquals(0, signature.getOrphanRevocations().size());
		for (XmlRevocationRef revocationRef : foundRevocationRefs) {
			assertNotNull(revocationRef.getDigestAlgoAndValue());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestMethod());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestValue());
			assertNotNull(revocationRef.getOrigins());
		}
	}
	
	@Test
	public void revocationOCSPRefsTest() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/cades/CAdES-Baseline_profile_LT/Sample_Set_15/Signature-CBp-LT-2.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports report = validator.validateDocument();
		// report.print();
		DiagnosticData diagnosticData = report.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlRevocationRef> foundRevocationRefs = signature.getAllFoundRevocationRefs();
		assertNotNull(foundRevocationRefs);
		assertEquals(3, foundRevocationRefs.size());
		assertEquals(3, signature.getFoundRevocationRefsByOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
		assertEquals(0, signature.getFoundRevocationRefsByOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS).size());
		assertEquals(3, signature.getOrphanRevocations().size());
		for (XmlRevocationRef revocationRef : foundRevocationRefs) {
			assertNotNull(revocationRef.getDigestAlgoAndValue());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestMethod());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestValue());
			assertNotNull(revocationRef.getOrigins());
			assertNotNull(revocationRef.getProducedAt());
			assertTrue(Utils.isStringNotEmpty(revocationRef.getResponderIdName()) || Utils.isArrayNotEmpty(revocationRef.getResponderIdKey()));
		}
	}
	
	@Test
	public void revocationRefsWithMultipleOrigins() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/cades/CAdES-X/Sample_Set_12/Signature-C-X-1.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports report = validator.validateDocument();

		DiagnosticData diagnosticData = report.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		List<XmlRevocationRef> allFoundRevocationRefs = signature.getAllFoundRevocationRefs();
		assertEquals(3, allFoundRevocationRefs.size());
		
		List<XmlFoundRevocation> allFoundRevocations = signature.getAllFoundRevocations();
		assertEquals(3, allFoundRevocations.size());

		List<String> revocationIds = new ArrayList<String>();
		for (XmlFoundRevocation revocation : allFoundRevocations) {
			assertNotNull(revocation.getType());
			
			assertTrue(revocation instanceof XmlOrphanRevocation);
			XmlOrphanRevocation orphanRevocation = (XmlOrphanRevocation) revocation;
			XmlOrphanToken orphanRevocationToken = orphanRevocation.getToken();
			assertNotNull(orphanRevocationToken);
			assertFalse(revocationIds.contains(orphanRevocationToken.getId()));
			revocationIds.add(orphanRevocationToken.getId());
			
			List<XmlRevocationRef> revocationRefs = revocation.getRevocationRefs();
			assertEquals(1, revocationRefs.size());
			
			XmlRevocationRef revocationRef = revocationRefs.get(0);
			assertEquals(2, revocationRef.getOrigins().size());
			assertNotNull(revocationRef.getDigestAlgoAndValue());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestMethod());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestValue());
		}
		
		List<XmlOrphanRevocation> allOrphanRevocations = diagnosticData.getAllOrphanRevocations();
		assertEquals(3, allOrphanRevocations.size());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
