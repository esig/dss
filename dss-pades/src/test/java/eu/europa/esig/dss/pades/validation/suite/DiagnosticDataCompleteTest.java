/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.validation.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

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
import eu.europa.esig.dss.pades.validation.PAdESSignature;
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

public class DiagnosticDataCompleteTest extends PKIFactoryAccess {

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
		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/validation/Signature-P-HU_POL-3.pdf"));
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
		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/validation/Signature-P-SK-6.pdf"));
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
		assertEquals("Signature1", signatureOne.getFirstFieldName());
		
		SignatureWrapper signatureTwo = signatures.get(1);
		assertEquals(2, signatureOne.getAllFoundRevocations().size());
		assertEquals(2, signatureOne.getRevocationIdsByType(RevocationType.CRL).size());
		assertEquals(0, signatureOne.getRevocationIdsByType(RevocationType.OCSP).size());
		assertEquals(0, signatureOne.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(0, signatureOne.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
		assertEquals(2, signatureOne.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.DSS_DICTIONARY).size());
		assertEquals(0, signatureTwo.getAllFoundRevocationRefs().size());
		assertEquals("Signature3", signatureTwo.getFirstFieldName());
		
		List<TimestampWrapper> timestamps= diagnosticData.getTimestampList();
		assertNotNull(timestamps);
		assertEquals(2, timestamps.size()); // one timestamp is skipped because of /Type /Sig (see DSS-1899)
		
		assertEquals(5, timestamps.get(0).getTimestampedObjects().size());
		assertEquals(TimestampType.SIGNATURE_TIMESTAMP, timestamps.get(0).getType());
		assertEquals(5, timestamps.get(1).getTimestampedObjects().size());
		assertEquals(TimestampType.SIGNATURE_TIMESTAMP, timestamps.get(1).getType());
		
	}
	
	@Test
	public void dssAndVriTest() {
		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/validation/Signature-P-BG_BOR-2.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports report = validator.validateDocument();
		// report.print();
		DiagnosticData diagnosticData = report.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertNotNull(signatures);
		
		SignatureWrapper signature = signatures.get(0);
		assertEquals(2, signature.getAllFoundRevocations().size());
		assertEquals(0, signature.getRevocationIdsByType(RevocationType.CRL).size());
		assertEquals(2, signature.getRevocationIdsByType(RevocationType.OCSP).size());
		assertEquals(0, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(0, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
		assertEquals(1, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.DSS_DICTIONARY).size());
		assertEquals(1, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.VRI_DICTIONARY).size());
		assertEquals(1, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.ADBE_REVOCATION_INFO_ARCHIVAL).size());
		
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
		List<String> usedTimestampIds = new ArrayList<>();
		for (TimestampWrapper timestamp : timestamps) {
			assertFalse(usedTimestampIds.contains(timestamp.getId()));
			usedTimestampIds.add(timestamp.getId());
			List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
			List<String> usedTimestampObjectIds = new ArrayList<>();
			for (XmlTimestampedObject timestampedObject : timestampedObjects) {
				assertFalse(usedTimestampObjectIds.contains(timestampedObject.getToken().getId()));
				usedTimestampObjectIds.add(timestampedObject.getToken().getId());
			}
		}
		
		SignatureWrapper secondSignature = diagnosticData.getSignatures().get(1);

		List<TimestampWrapper> secondSignatureTimestamps = secondSignature.getTimestampList();
		assertEquals(2, secondSignatureTimestamps.size());
		TimestampWrapper signatureTimestamp = secondSignatureTimestamps.get(0);
		assertEquals(4, signatureTimestamp.getTimestampedObjects().size());
		assertEquals(TimestampType.SIGNATURE_TIMESTAMP, signatureTimestamp.getType());
        
        TimestampWrapper archiveTimestamp = null;
        int archiveTimestamps = 0;
        for (TimestampWrapper timestamp : timestamps) {
        	if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
        		archiveTimestamp = timestamp;
        		++archiveTimestamps;
        	}
        }
        assertNotNull(archiveTimestamp);
        assertEquals(1, archiveTimestamps);

        List<String> checkedIds = new ArrayList<>();
        
        assertEquals(5, archiveTimestamp.getTimestampedSignatureIds().size());
        checkedIds.add(archiveTimestamp.getTimestampedSignatureIds().get(0));
        
        List<String> timestampedSignedDataIds = archiveTimestamp.getTimestampedSignedDataIds();
        assertEquals(5, timestampedSignedDataIds.size());
        for (String id : timestampedSignedDataIds) {
            assertFalse(checkedIds.contains(id));
            checkedIds.add(id);
        }
        
        List<String> timestampedCertificateIds = archiveTimestamp.getTimestampedCertificateIds();
        assertEquals(18, timestampedCertificateIds.size());
        for (String id : timestampedCertificateIds) {
            assertFalse(checkedIds.contains(id));
            checkedIds.add(id);
        }
        
        List<String> timestampedRevocationIds = archiveTimestamp.getTimestampedRevocationIds();
        assertEquals(4, timestampedRevocationIds.size());
        for (String id : timestampedRevocationIds) {
            assertFalse(checkedIds.contains(id));
            checkedIds.add(id);
        }
        
        List<String> timestampedTimestampIds = archiveTimestamp.getTimestampedTimestampIds();
        assertEquals(2, timestampedTimestampIds.size());
        for (String id : timestampedTimestampIds) {
            assertFalse(checkedIds.contains(id));
            checkedIds.add(id);
        }
        
        assertEquals(30, checkedIds.size());
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
		byte[] contents = padesSignature.getPdfRevision().getPdfSigDictInfo().getContents();
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
