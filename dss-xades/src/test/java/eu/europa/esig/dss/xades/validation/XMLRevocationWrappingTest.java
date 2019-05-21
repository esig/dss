package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.jaxb.diagnostic.XmlFoundRevocations;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRelatedRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocationRef;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.RevocationType;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.XmlRevocationOrigin;
import eu.europa.esig.dss.validation.XmlRevocationRefLocation;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class XMLRevocationWrappingTest extends PKIFactoryAccess {
	
	@Test
	public void revocationOriginTest() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/HU_POL/Signature-X-HU_POL-3.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		int revocationSignatureOriginCounter = 0;
		
		Set<RevocationWrapper> revocationData = diagnosticData.getAllRevocationData();
		Set<String> revocationIds = new HashSet<String>();
		for (RevocationWrapper revocation : revocationData) {
			assertNotNull(revocation.getRevocationType());
			assertNotNull(revocation.getOrigin());
			if (XmlRevocationOrigin.SIGNATURE.equals(revocation.getOrigin())) {
				revocationSignatureOriginCounter++;
			}
			revocationIds.add(revocation.getId());
		}
		assertEquals(4, revocationSignatureOriginCounter);
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByType(diagnosticData.getFirstSignatureId(), 
				RevocationType.CRL).size());
		assertEquals(4, diagnosticData.getAllRevocationForSignatureByType(diagnosticData.getFirstSignatureId(), 
				RevocationType.OCSP).size());
		assertEquals(2, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_REVOCATION_VALUES).size());
		assertEquals(2, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_TIMESTAMP_REVOCATION_VALUES).size());
		
		eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData xmlDiagnosticData = reports.getDiagnosticDataJaxb();
		List<XmlSignature> xmlSignatures = xmlDiagnosticData.getSignatures();
		assertNotNull(xmlSignatures);
		for (XmlSignature signature : xmlSignatures) {
			List<XmlRelatedRevocation> revocationRefs = signature.getFoundRevocations().getRelatedRevocations();
			assertNotNull(revocationRefs);
			assertEquals(4, revocationRefs.size());
			for (XmlRelatedRevocation revocation : revocationRefs) {
				assertNotNull(revocation.getRevocation());
				assertNotNull(revocation.getType());
				assertTrue(revocationIds.contains(revocation.getRevocation().getId()));
			}
		}
	}
	
	@Test
	public void revocationOriginThreeSignaturesTest() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/HR_FIN/Signature-X-HR_FIN-1.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		int revocationSignatureOriginCounter = 0;
		Set<RevocationWrapper> revocationData = diagnosticData.getAllRevocationData();
		Set<String> revocationIds = new HashSet<String>();
		for (RevocationWrapper revocation : revocationData) {
			assertNotNull(revocation.getRevocationType());
			assertNotNull(revocation.getOrigin());
			if (XmlRevocationOrigin.SIGNATURE.equals(revocation.getOrigin())) {
				revocationSignatureOriginCounter++;
			}
			revocationIds.add(revocation.getId());
		}
		assertEquals(1, revocationSignatureOriginCounter);
		assertEquals(1, diagnosticData.getAllRevocationForSignatureByType(diagnosticData.getFirstSignatureId(),
				RevocationType.CRL).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByType(diagnosticData.getFirstSignatureId(), 
				RevocationType.OCSP).size());
		assertEquals(1, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.CRL, XmlRevocationOrigin.INTERNAL_REVOCATION_VALUES).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.CRL, XmlRevocationOrigin.INTERNAL_TIMESTAMP_REVOCATION_VALUES).size());
		
		eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData xmlDiagnosticData = reports.getDiagnosticDataJaxb();
		List<XmlSignature> xmlSignatures = xmlDiagnosticData.getSignatures();
		assertNotNull(xmlSignatures);
		for (XmlSignature signature : xmlSignatures) {
			List<XmlRelatedRevocation> revocationRefs = signature.getFoundRevocations().getRelatedRevocations();
			assertNotNull(revocationRefs);
			for (XmlRelatedRevocation revocation : revocationRefs) {
				assertNotNull(revocation.getRevocation());
				assertNotNull(revocation.getType());
				assertTrue(revocationIds.contains(revocation.getRevocation().getId()));
			}
		}
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(3, signatures.size());
		
		assertEquals(1, diagnosticData.getAllRevocationForSignature(signatures.get(0).getId()).size());
		assertEquals(1, diagnosticData.getAllRevocationForSignature(signatures.get(1).getId()).size());
		assertEquals(1, diagnosticData.getAllRevocationForSignature(signatures.get(2).getId()).size());
		
		// Same CRL has been inserted 3 times
		assertEquals(1, diagnosticData.getAllRevocationData().size());

	}
	
	@Test
	public void revocationReferencesTest() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/ES/Signature-X-ES-100.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		XmlFoundRevocations foundRevocations = signature.getFoundRevocations();
		assertNotNull(foundRevocations);
		assertEquals(4, foundRevocations.getRelatedRevocations().size());
		assertEquals(4, signature.getFoundRevocationRefsByLocation(XmlRevocationRefLocation.COMPLETE_REVOCATION_REFS).size());
		assertEquals(0, signature.getFoundRevocationRefsByLocation(XmlRevocationRefLocation.ATTRIBUTE_REVOCATION_REFS).size());
		int ocspResponses = 0;
		List<String> revocationDigests = new ArrayList<String>();
		for (XmlRevocationRef revocationRef : signature.getFoundRevocationRefsByLocation(XmlRevocationRefLocation.COMPLETE_REVOCATION_REFS)) {
			assertNotNull(revocationRef.getDigestAlgoAndValue());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestMethod());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestValue());
			assertNotNull(revocationRef.getLocation());
			if (revocationRef.getProducedAt() != null) {
				assertTrue(Utils.isStringNotEmpty(revocationRef.getResponderIdName()) || Utils.isArrayNotEmpty(revocationRef.getResponderIdKey()));
				ocspResponses++;
			}
			String base64 = Utils.toBase64(revocationRef.getDigestAlgoAndValue().getDigestValue());
			assertFalse(revocationDigests.contains(base64));
			revocationDigests.add(base64);
		}
		assertEquals(signature.getRevocationIdsByType(RevocationType.OCSP).size(), ocspResponses);
	}
	
	@Test
	public void ocspWrongRefTest() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/BG/Signature-X-BG-1.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlRevocationRef> foundRevocationRefs = signature.getAllFoundRevocationRefs();
		assertNotNull(foundRevocationRefs);
		assertEquals(0, foundRevocationRefs.size());
		List<XmlRevocationRef> relatedRevocationRefs = signature.getAllRelatedRevocationRefs();
		assertNotNull(relatedRevocationRefs);
		assertEquals(0, relatedRevocationRefs.size());
		assertEquals(0, signature.getFoundRevocationRefsByLocation(XmlRevocationRefLocation.COMPLETE_REVOCATION_REFS).size());
		assertEquals(0, signature.getFoundRevocationRefsByLocation(XmlRevocationRefLocation.ATTRIBUTE_REVOCATION_REFS).size());
	}
	
	@Test
	public void ocspRefWithByKeyResponderIdTest() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/UK_ELD/Signature-X-UK_ELD-4.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		XmlFoundRevocations foundRevocations = signature.getFoundRevocations();
		assertNotNull(foundRevocations);
		assertEquals(1, foundRevocations.getRelatedRevocations().size());
		assertEquals(0, signature.getOrphanRevocations().size());
		assertEquals(1, signature.getFoundRevocationRefsByLocation(XmlRevocationRefLocation.COMPLETE_REVOCATION_REFS).size());
		assertEquals(0, signature.getFoundRevocationRefsByLocation(XmlRevocationRefLocation.ATTRIBUTE_REVOCATION_REFS).size());
		XmlRevocationRef revocationRef = foundRevocations.getRelatedRevocations().get(0).getRevocationReferences().get(0);
		assertNotNull(revocationRef.getLocation());
		assertNotNull(revocationRef.getDigestAlgoAndValue());
		assertNotNull(revocationRef.getProducedAt());
		assertNotNull(revocationRef.getResponderIdKey());
	}
	
	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
