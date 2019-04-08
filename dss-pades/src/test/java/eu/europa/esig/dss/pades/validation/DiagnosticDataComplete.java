package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedObject;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.RevocationType;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.XmlRevocationOrigin;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.x509.TimestampLocation;
import eu.europa.esig.dss.x509.TimestampType;

public class DiagnosticDataComplete extends PKIFactoryAccess {

	@Test
	public void pdfSignatureDictionaryTest() {
		
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/AD-RB.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		Set<SignatureWrapper> signatures = diagnosticData.getAllSignatures();
		assertNotNull(signatures);
		for (SignatureWrapper signature : signatures) {
			List<BigInteger> byteRange = signature.getSignatureByteRange();
			assertNotNull(byteRange);
			assertEquals(4, byteRange.size());
			assertEquals(-1, byteRange.get(1).compareTo(byteRange.get(2)));
		}
		
	}
	
	@Test
	public void revocationOriginTest() {
		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/plugtest/esig2014/ESIG-PAdES/HU_POL/Signature-P-HU_POL-3.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports report = validator.validateDocument();
		// report.print();
		DiagnosticData diagnosticData = report.getDiagnosticData();

		assertEquals(3, diagnosticData.getAllRevocationForSignatureByType(diagnosticData.getFirstSignatureId(), 
				RevocationType.CRL).size());
		assertEquals(4, diagnosticData.getAllRevocationForSignatureByType(diagnosticData.getFirstSignatureId(), 
				RevocationType.OCSP).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.CRL, XmlRevocationOrigin.INTERNAL_REVOCATION_VALUES).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.CRL, XmlRevocationOrigin.INTERNAL_TIMESTAMP_REVOCATION_VALUES).size());
		assertEquals(3, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.CRL, XmlRevocationOrigin.INTERNAL_DSS).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_REVOCATION_VALUES).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_TIMESTAMP_REVOCATION_VALUES).size());
		assertEquals(4, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_DSS).size());
	}
	
	@Test
	public void multiSignedDocRevocationRefTest() throws Exception {
		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/plugtest/esig2014/ESIG-PAdES/SK/Signature-P-SK-6.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports report = validator.validateDocument();
		// report.print();
		DiagnosticData diagnosticData = report.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertNotNull(signatures);
		assertEquals(2, signatures.size());
		
		SignatureWrapper signatureOne = signatures.get(0);
		assertEquals(2, diagnosticData.getAllRevocationForSignature(signatureOne.getId()).size());
		assertEquals(2, diagnosticData.getAllRevocationForSignatureByType(signatureOne.getId(), RevocationType.CRL).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByType(signatureOne.getId(), RevocationType.OCSP).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signatureOne.getId(), 
				RevocationType.CRL, XmlRevocationOrigin.INTERNAL_REVOCATION_VALUES).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signatureOne.getId(), 
				RevocationType.CRL, XmlRevocationOrigin.INTERNAL_TIMESTAMP_REVOCATION_VALUES).size());
		assertEquals(2, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signatureOne.getId(), 
				RevocationType.CRL, XmlRevocationOrigin.INTERNAL_DSS).size());
		
		assertEquals(0, signatureOne.getAllFoundRevocationRefs().size());
		assertEquals("Signature1", signatureOne.getSignatureFieldName());
		
		SignatureWrapper signatureTwo = signatures.get(1);
		assertEquals(2, diagnosticData.getAllRevocationForSignature(signatureTwo.getId()).size());
		assertEquals(2, diagnosticData.getAllRevocationForSignatureByType(signatureTwo.getId(), RevocationType.CRL).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByType(signatureTwo.getId(), RevocationType.OCSP).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signatureTwo.getId(), 
				RevocationType.CRL, XmlRevocationOrigin.INTERNAL_REVOCATION_VALUES).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signatureTwo.getId(), 
				RevocationType.CRL, XmlRevocationOrigin.INTERNAL_TIMESTAMP_REVOCATION_VALUES).size());
		assertEquals(2, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signatureTwo.getId(), 
				RevocationType.CRL, XmlRevocationOrigin.INTERNAL_DSS).size());
		assertEquals(0, signatureTwo.getAllFoundRevocationRefs().size());
		assertEquals("Signature3", signatureTwo.getSignatureFieldName());
		
		List<TimestampWrapper> timestamps= diagnosticData.getTimestamps();
		assertNotNull(timestamps);
		assertEquals(3, timestamps.size());
		assertEquals(2, timestamps.get(0).getTimestampedObjects().size());
		assertEquals(TimestampType.SIGNATURE_TIMESTAMP, timestamps.get(0).getType());
		assertEquals(2, timestamps.get(2).getTimestampedObjects().size());
		assertEquals(TimestampType.SIGNATURE_TIMESTAMP, timestamps.get(2).getType());
		
		TimestampWrapper archiveTimestamp = timestamps.get(1);
		assertEquals(TimestampType.ARCHIVE_TIMESTAMP, archiveTimestamp.getType());
		assertEquals(1, archiveTimestamp.getTimestampedSignatures().size());
		List<String> timestampedCertificateIds = archiveTimestamp.getTimestampedCertificateIds();
		assertEquals(4, timestampedCertificateIds.size());
		List<String> checkedIds = new ArrayList<String>();
		for (String id : timestampedCertificateIds) {
			assertFalse(checkedIds.contains(id));
			checkedIds.add(id);
		}
		List<String> timestampedRevocationIds = archiveTimestamp.getTimestampedRevocationIds();
		assertEquals(2, timestampedRevocationIds.size());
		for (String id : timestampedRevocationIds) {
			assertFalse(checkedIds.contains(id));
			checkedIds.add(id);
		}
		List<String> timestampedTimestampIds = archiveTimestamp.getTimestampedTimestampIds();
		assertEquals(1, timestampedTimestampIds.size());
		for (String id : timestampedTimestampIds) {
			assertFalse(checkedIds.contains(id));
			checkedIds.add(id);
		}
		assertEquals(7, checkedIds.size());
	}
	
	@Test
	public void dssAndVriTest() {
		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/plugtest/esig2014/ESIG-PAdES/BG_BOR/Signature-P-BG_BOR-2.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports report = validator.validateDocument();
		// System.out.println(report.getXmlDiagnosticData().replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", ""));
		DiagnosticData diagnosticData = report.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertNotNull(signatures);
		
		SignatureWrapper signature = signatures.get(0);
		assertEquals(2, diagnosticData.getAllRevocationForSignature(signature.getId()).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByType(signature.getId(), RevocationType.CRL).size());
		assertEquals(2, diagnosticData.getAllRevocationForSignatureByType(signature.getId(), RevocationType.OCSP).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signature.getId(), 
				RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_REVOCATION_VALUES).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signature.getId(), 
				RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_TIMESTAMP_REVOCATION_VALUES).size());
		assertEquals(1, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signature.getId(), 
				RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_DSS).size());
		assertEquals(1, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signature.getId(), 
				RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_VRI).size());
		
		List<TimestampWrapper> timestamps = signature.getTimestampList();
		assertNotNull(timestamps);
		assertEquals(2, timestamps.size());
		List<TimestampWrapper> docTimestamps = signature.getTimestampListByLocation(TimestampLocation.DOC_TIMESTAMP);
		assertNotNull(docTimestamps);
		assertEquals(1, docTimestamps.size());
	}
	
	@Test
	public void fiveSignaturesOWithSingleTimestampTest() {
		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/validation/pades-5-signatures-and-1-document-timestamp.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports report = validator.validateDocument();
		// System.out.println(report.getXmlDiagnosticData().replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", ""));
		DiagnosticData diagnosticData = report.getDiagnosticData();
		assertNotNull(diagnosticData);
		List<TimestampWrapper> timestamps = diagnosticData.getTimestamps();
		assertNotNull(timestamps);
		assertEquals(3, timestamps.size());
		List<String> usedTimestampIds = new ArrayList<String>();
		for (TimestampWrapper timestamp : timestamps) {
			assertFalse(usedTimestampIds.contains(timestamp.getId()));
			usedTimestampIds.add(timestamp.getId());
			List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
			List<String> usedTimestampObjectIds = new ArrayList<String>();
			for (XmlTimestampedObject timestampedObject : timestampedObjects) {
				assertFalse(usedTimestampObjectIds.contains(timestampedObject.getToken().getId()));
				usedTimestampObjectIds.add(timestampedObject.getToken().getId());
			}
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
}
