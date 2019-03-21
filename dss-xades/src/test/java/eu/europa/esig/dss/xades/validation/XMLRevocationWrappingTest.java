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
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocationRef;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.RevocationOriginType;
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
		int revocationValuesOriginCounter = 0;
		int timestampRevocationDataOriginCounter = 0;
		Set<RevocationWrapper> revocationData = diagnosticData.getAllRevocationData();
		Set<String> revocationIds = new HashSet<String>();
		for (RevocationWrapper revocation : revocationData) {
			assertNotNull(revocation.getRevocationType());
			assertNotNull(revocation.getOrigin());
			if (RevocationOriginType.INTERNAL_REVOCATION_VALUES.equals(revocation.getOrigin())) {
				revocationValuesOriginCounter++;
			}
			if (RevocationOriginType.INTERNAL_TIMESTAMP_REVOCATION_VALUES.equals(revocation.getOrigin())) {
				timestampRevocationDataOriginCounter++;
			}
			revocationIds.add(revocation.getId());
		}
		assertEquals(2, revocationValuesOriginCounter);
		assertEquals(2, timestampRevocationDataOriginCounter);
		
		eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData xmlDiagnosticData = reports.getDiagnosticDataJaxb();
		List<XmlSignature> xmlSignatures = xmlDiagnosticData.getSignatures();
		assertNotNull(xmlSignatures);
		for (XmlSignature signature : xmlSignatures) {
			List<XmlRevocationRef> revocationRefs = signature.getRevocationRefs();
			assertNotNull(revocationRefs);
			assertEquals(4, revocationRefs.size());
			for (XmlRevocationRef revocation : revocationRefs) {
				assertNotNull(revocation.getId());
				assertNotNull(revocation.getType());
				assertNotNull(revocation.getOrigin());
				assertTrue(revocationIds.contains(revocation.getId()));
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
		int revocationValuesOriginCounter = 0;
		int timestampRevocationDataOriginCounter = 0;
		Set<RevocationWrapper> revocationData = diagnosticData.getAllRevocationData();
		Set<String> revocationIds = new HashSet<String>();
		for (RevocationWrapper revocation : revocationData) {
			assertNotNull(revocation.getRevocationType());
			assertNotNull(revocation.getOrigin());
			if (RevocationOriginType.INTERNAL_REVOCATION_VALUES.equals(revocation.getOrigin())) {
				revocationValuesOriginCounter++;
			}
			if (RevocationOriginType.INTERNAL_TIMESTAMP_REVOCATION_VALUES.equals(revocation.getOrigin())) {
				timestampRevocationDataOriginCounter++;
			}
			revocationIds.add(revocation.getId());
		}
		assertEquals(2, revocationValuesOriginCounter);
		assertEquals(0, timestampRevocationDataOriginCounter);
		
		eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData xmlDiagnosticData = reports.getDiagnosticDataJaxb();
		List<XmlSignature> xmlSignatures = xmlDiagnosticData.getSignatures();
		assertNotNull(xmlSignatures);
		for (XmlSignature signature : xmlSignatures) {
			List<XmlRevocationRef> revocationRefs = signature.getRevocationRefs();
			assertNotNull(revocationRefs);
			for (XmlRevocationRef revocation : revocationRefs) {
				assertNotNull(revocation.getId());
				assertNotNull(revocation.getType());
				assertNotNull(revocation.getOrigin());
				assertTrue(revocationIds.contains(revocation.getId()));
				assertTrue(presentOnlyOnce(revocationRefs, revocation));
			}
		}
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(3, signatures.size());
		
		assertEquals(1, diagnosticData.getAllRevocationForSignature(signatures.get(0).getId()).size());
		assertEquals(1, diagnosticData.getAllRevocationForSignature(signatures.get(1).getId()).size());
		assertEquals(1, diagnosticData.getAllRevocationForSignature(signatures.get(2).getId()).size());
		
	}
	
	public boolean presentOnlyOnce(List<XmlRevocationRef> list, XmlRevocationRef revocation) 
	{
	    int numCount = 0;
	    for (XmlRevocationRef thisRev : list) {
	        if (thisRev.getId().equals(revocation.getId())) numCount++;
	    }
	    return numCount == 1;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
