package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateRevocationRef;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.RevocationOriginType;
import eu.europa.esig.dss.validation.RevocationType;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class XMLRevocationWrappingTest extends PKIFactoryAccess {
	
	@Test
	public void revocationOriginTest() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/HU_POL/Signature-X-HU_POL-3.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		int revocationSignatureOriginCounter = 0;
		
		Set<RevocationWrapper> revocationData = diagnosticData.getAllRevocationData();
		Set<String> revocationIds = new HashSet<String>();
		for (RevocationWrapper revocation : revocationData) {
			assertNotNull(revocation.getRevocationType());
			assertNotNull(revocation.getOrigin());
			if (RevocationOriginType.SIGNATURE.equals(revocation.getOrigin())) {
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
				RevocationType.OCSP, RevocationOriginType.INTERNAL_REVOCATION_VALUES).size());
		assertEquals(2, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.OCSP, RevocationOriginType.INTERNAL_TIMESTAMP_REVOCATION_VALUES).size());
		
		eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData xmlDiagnosticData = reports.getDiagnosticDataJaxb();
		List<XmlSignature> xmlSignatures = xmlDiagnosticData.getSignatures();
		assertNotNull(xmlSignatures);
		for (XmlSignature signature : xmlSignatures) {
			List<XmlCertificateRevocationRef> revocationRefs = signature.getRelatedRevocations();
			assertNotNull(revocationRefs);
			assertEquals(4, revocationRefs.size());
			for (XmlCertificateRevocationRef revocation : revocationRefs) {
				assertNotNull(revocation.getRevocationId());
				assertNotNull(revocation.getCertificateId());
				assertNotNull(revocation.getType());
				assertNotNull(revocation.getOrigin());
				assertTrue(revocationIds.contains(revocation.getRevocationId()));
				assertNotNull(diagnosticData.getUsedCertificateById(revocation.getCertificateId()));
			}
		}
	}
	
	@Test
	public void revocationOriginThreeSignaturesTest() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/HR_FIN/Signature-X-HR_FIN-1.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		int revocationSignatureOriginCounter = 0;
		Set<RevocationWrapper> revocationData = diagnosticData.getAllRevocationData();
		Set<String> revocationIds = new HashSet<String>();
		for (RevocationWrapper revocation : revocationData) {
			assertNotNull(revocation.getRevocationType());
			assertNotNull(revocation.getOrigin());
			if (RevocationOriginType.SIGNATURE.equals(revocation.getOrigin())) {
				revocationSignatureOriginCounter++;
			}
			revocationIds.add(revocation.getId());
		}
		assertEquals(1, revocationSignatureOriginCounter);
		assertEquals(2, diagnosticData.getAllRevocationForSignatureByType(diagnosticData.getFirstSignatureId(), 
				RevocationType.CRL).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByType(diagnosticData.getFirstSignatureId(), 
				RevocationType.OCSP).size());
		assertEquals(2, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.CRL, RevocationOriginType.INTERNAL_REVOCATION_VALUES).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.CRL, RevocationOriginType.INTERNAL_TIMESTAMP_REVOCATION_VALUES).size());
		
		eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData xmlDiagnosticData = reports.getDiagnosticDataJaxb();
		List<XmlSignature> xmlSignatures = xmlDiagnosticData.getSignatures();
		assertNotNull(xmlSignatures);
		for (XmlSignature signature : xmlSignatures) {
			List<XmlCertificateRevocationRef> revocationRefs = signature.getRelatedRevocations();
			assertNotNull(revocationRefs);
			for (XmlCertificateRevocationRef revocation : revocationRefs) {
				assertNotNull(revocation.getCertificateId());
				assertNotNull(revocation.getRevocationId());
				assertNotNull(revocation.getType());
				assertNotNull(revocation.getOrigin());
				assertTrue(revocationIds.contains(revocation.getRevocationId()));
				assertTrue(presentOnlyOnce(revocationRefs, revocation));
				assertNotNull(diagnosticData.getUsedCertificateById(revocation.getCertificateId()));
			}
		}
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(3, signatures.size());
		
		assertEquals(2, diagnosticData.getAllRevocationForSignature(signatures.get(0).getId()).size());
		assertEquals(2, diagnosticData.getAllRevocationForSignature(signatures.get(1).getId()).size());
		assertEquals(2, diagnosticData.getAllRevocationForSignature(signatures.get(2).getId()).size());
		
	}
	
	public boolean presentOnlyOnce(List<XmlCertificateRevocationRef> list, XmlCertificateRevocationRef revocation) 
	{
	    int numCount = 0;
	    for (XmlCertificateRevocationRef thisRev : list) {
	        if ((thisRev.getCertificateId() + thisRev.getRevocationId()).equals(
	        		(revocation.getCertificateId() + revocation.getRevocationId()))) numCount++;
	    }
	    return numCount == 1;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
