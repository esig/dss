package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureDigestReference;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.TimestampLocation;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.jaxb.POEProvisioningType;
import eu.europa.esig.validationreport.jaxb.SignatureReferenceType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

public class DiagnosticDataComplete extends PKIFactoryAccess {

	@Test
	public void pdfSignatureDictionaryTest() {
		
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/AD-RB.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
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
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports report = validator.validateDocument();
		// report.print();
		DiagnosticData diagnosticData = report.getDiagnosticData();
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

		assertEquals(3, signature.getRevocationIdsByType(RevocationType.CRL).size());
		assertEquals(4, signature.getRevocationIdsByType(RevocationType.OCSP).size());
		assertEquals(0, signature.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(0, signature.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
		assertEquals(3, signature.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.DSS_DICTIONARY).size());
		assertEquals(0, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(0, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
		assertEquals(4, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.DSS_DICTIONARY).size());
	}
	
	@Test
	public void multiSignedDocRevocationRefTest() throws Exception {
		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/plugtest/esig2014/ESIG-PAdES/SK/Signature-P-SK-6.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports report = validator.validateDocument();
		// report.print();
		DiagnosticData diagnosticData = report.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertNotNull(signatures);
		assertEquals(2, signatures.size());
		
		SignatureWrapper signatureOne = signatures.get(0);
		assertEquals(2, signatureOne.getAllFoundRevocations().size());
		assertEquals(2, signatureOne.getRevocationIdsByType(RevocationType.CRL).size());
		assertEquals(0, signatureOne.getRevocationIdsByType(RevocationType.OCSP).size());
		assertEquals(0, signatureOne.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(0, signatureOne.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
		assertEquals(2, signatureOne.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.DSS_DICTIONARY).size());
		
		assertEquals(0, signatureOne.getAllFoundRevocationRefs().size());
		assertEquals("Signature1", signatureOne.getSignatureFieldName());
		
		SignatureWrapper signatureTwo = signatures.get(1);
		assertEquals(2, signatureOne.getAllFoundRevocations().size());
		assertEquals(2, signatureOne.getRevocationIdsByType(RevocationType.CRL).size());
		assertEquals(0, signatureOne.getRevocationIdsByType(RevocationType.OCSP).size());
		assertEquals(0, signatureOne.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(0, signatureOne.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
		assertEquals(2, signatureOne.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.DSS_DICTIONARY).size());
		assertEquals(0, signatureTwo.getAllFoundRevocationRefs().size());
		assertEquals("Signature3", signatureTwo.getSignatureFieldName());
		
		List<TimestampWrapper> timestamps= diagnosticData.getTimestampList();
		assertNotNull(timestamps);
		assertEquals(3, timestamps.size());
		assertEquals(5, timestamps.get(0).getTimestampedObjects().size());
		assertEquals(TimestampType.SIGNATURE_TIMESTAMP, timestamps.get(0).getType());
		assertEquals(5, timestamps.get(2).getTimestampedObjects().size());
		assertEquals(TimestampType.SIGNATURE_TIMESTAMP, timestamps.get(2).getType());
		
		TimestampWrapper archiveTimestamp = timestamps.get(1);
		assertEquals(TimestampType.ARCHIVE_TIMESTAMP, archiveTimestamp.getType());

		List<String> checkedIds = new ArrayList<String>();
		
		assertEquals(1, archiveTimestamp.getTimestampedSignatureIds().size());
		checkedIds.add(archiveTimestamp.getTimestampedSignatureIds().get(0));
		
		List<String> timestampedSignedDataIds = archiveTimestamp.getTimestampedSignedDataIds();
		assertEquals(1, timestampedSignedDataIds.size());
		for (String id : timestampedSignedDataIds) {
			assertFalse(checkedIds.contains(id));
			checkedIds.add(id);
		}
		
		List<String> timestampedCertificateIds = archiveTimestamp.getTimestampedCertificateIds();
		assertEquals(4, timestampedCertificateIds.size());
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
		
		assertEquals(9, checkedIds.size());
		
	}
	
	@Test
	public void dssAndVriTest() {
		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/plugtest/esig2014/ESIG-PAdES/BG_BOR/Signature-P-BG_BOR-2.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports report = validator.validateDocument();
		// report.print();
		DiagnosticData diagnosticData = report.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertNotNull(signatures);
		
		SignatureWrapper signature = signatures.get(0);
		assertEquals(1, signature.getAllFoundRevocations().size());
		assertEquals(0, signature.getRevocationIdsByType(RevocationType.CRL).size());
		assertEquals(1, signature.getRevocationIdsByType(RevocationType.OCSP).size());
		assertEquals(0, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(0, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
		assertEquals(1, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.DSS_DICTIONARY).size());
		assertEquals(1, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.VRI_DICTIONARY).size());
		
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
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports report = validator.validateDocument();
		// System.out.println(report.getXmlDiagnosticData().replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", ""));
		DiagnosticData diagnosticData = report.getDiagnosticData();
		assertNotNull(diagnosticData);
		List<TimestampWrapper> timestamps = diagnosticData.getTimestampList();
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
	
	@Test
	public void signatureDigestReferenceTest() throws IOException {
		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/validation/pdf-signed-original.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports report = validator.validateDocument();
		
		DiagnosticData diagnosticData = report.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		XmlSignatureDigestReference signatureDigestReference = signature.getSignatureDigestReference();
		assertNotNull(signatureDigestReference);
		
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		PAdESSignature padesSignature = (PAdESSignature) signatures.get(0);
		byte[] contents = padesSignature.getPdfSignatureInfo().getContents();
		byte[] digest = DSSUtils.digest(signatureDigestReference.getDigestMethod(), contents);
		
		String signatureReferenceDigestValue = Utils.toBase64(signatureDigestReference.getDigestValue());
		String signatureElementDigestValue = Utils.toBase64(digest);
		assertEquals(signatureReferenceDigestValue, signatureElementDigestValue);
	}
	
	@Test
	public void SignatureDigestReferencePresenceTest() throws IOException {
		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/validation/PAdES-LTA.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports report = validator.validateDocument();
		
		ValidationReportType etsiValidationReport = report.getEtsiValidationReportJaxb();
		List<ValidationObjectType> validationObjects = etsiValidationReport.getSignatureValidationObjects().getValidationObject();
		int timestampCounter = 0;
		for (ValidationObjectType validationObject : validationObjects) {
			if (ObjectType.TIMESTAMP.equals(validationObject.getObjectType())) {
				POEProvisioningType poeProvisioning = validationObject.getPOEProvisioning();
				List<SignatureReferenceType> signatureReferences = poeProvisioning.getSignatureReference();
				assertEquals(1, signatureReferences.size());
				SignatureReferenceType signatureReferenceType = signatureReferences.get(0);
				assertNotNull(signatureReferenceType.getDigestMethod());
				assertNotNull(signatureReferenceType.getDigestValue());
				assertNull(signatureReferenceType.getCanonicalizationMethod());
				assertNull(signatureReferenceType.getXAdESSignaturePtr());
				timestampCounter++;
			}
		}
		assertEquals(1, timestampCounter);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
}
