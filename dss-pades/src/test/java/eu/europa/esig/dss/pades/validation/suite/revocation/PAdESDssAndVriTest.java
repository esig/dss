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
package eu.europa.esig.dss.pades.validation.suite.revocation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.validationreport.jaxb.SATimestampType;
import eu.europa.esig.validationreport.jaxb.SignatureAttributesType;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;

import javax.xml.bind.JAXBElement;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESDssAndVriTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/Signature-P-BG_BOR-2.pdf"));
	}

	@Override
	protected void checkValidationContext(SignedDocumentValidator validator) {
		super.checkValidationContext(validator);

		assertTrue(validator instanceof PDFDocumentValidator);
		PDFDocumentValidator pdfDocumentValidator = (PDFDocumentValidator) validator;

		assertEquals(1, pdfDocumentValidator.getSignatures().size());
		assertEquals(1, pdfDocumentValidator.getDssDictionaries().size());
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		
		SignatureWrapper signature = signatures.get(0);
		assertEquals(2, signature.foundRevocations().getRelatedRevocationData().size());
		assertEquals(0, signature.foundRevocations().getOrphanRevocationData().size());
		assertEquals(0, signature.foundRevocations().getRelatedRevocationsByType(RevocationType.CRL).size());
		assertEquals(0, signature.foundRevocations().getOrphanRevocationsByType(RevocationType.CRL).size());
		assertEquals(2, signature.foundRevocations().getRelatedRevocationsByType(RevocationType.OCSP).size());
		assertEquals(0, signature.foundRevocations().getOrphanRevocationsByType(RevocationType.OCSP).size());
		assertEquals(0, signature.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.REVOCATION_VALUES).size() +
				signature.foundRevocations().getOrphanRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(0, signature.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size() +
				signature.foundRevocations().getOrphanRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
		assertEquals(1, signature.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.DSS_DICTIONARY).size() +
				signature.foundRevocations().getOrphanRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.DSS_DICTIONARY).size());
		assertEquals(1, signature.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.VRI_DICTIONARY).size() +
				signature.foundRevocations().getOrphanRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.VRI_DICTIONARY).size());
		assertEquals(1, signature.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.ADBE_REVOCATION_INFO_ARCHIVAL).size() +
				signature.foundRevocations().getOrphanRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.ADBE_REVOCATION_INFO_ARCHIVAL).size());
		
		List<TimestampWrapper> timestamps = signature.getTimestampList();
		assertNotNull(timestamps);
		assertEquals(2, timestamps.size());
		List<TimestampWrapper> docTimestamps = signature.getTimestampListByType(TimestampType.DOCUMENT_TIMESTAMP);
		assertNotNull(docTimestamps);
		assertEquals(1, docTimestamps.size());
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signature.isSigningCertificateIdentified());
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void validateETSISignatureAttributes(SignatureAttributesType signatureAttributes) {
		super.validateETSISignatureAttributes(signatureAttributes);
		
		assertNotNull(signatureAttributes);
		List<Object> attributesList = signatureAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat();
		assertTrue(Utils.isCollectionNotEmpty(attributesList));
		List<SATimestampType> foundTimestamps = new ArrayList<>();
		int docTimestampsCounter = 0;
		int sigTimestampsCounter = 0;
		int archiveTimestampsCounter = 0;
		for (Object object : attributesList) {
			JAXBElement<?> element = (JAXBElement<?>) object;
			if (element.getValue() instanceof SATimestampType) {
				SATimestampType saTimestamp = (SATimestampType) element.getValue();
				assertTrue(Utils.isCollectionNotEmpty(saTimestamp.getAttributeObject()));
				assertNotNull(saTimestamp.getTimeStampValue());
				foundTimestamps.add(saTimestamp);
			}
			if (element.getName().getLocalPart().equals("ArchiveTimeStamp")) {
				archiveTimestampsCounter++;
			}
			if (element.getName().getLocalPart().equals("DocTimeStamp")) {
				docTimestampsCounter++;
			}
			if (element.getName().getLocalPart().equals("SignatureTimeStamp")) {
				sigTimestampsCounter++;
			}
		}
		assertEquals(2, foundTimestamps.size());
		assertEquals(1, sigTimestampsCounter);
		assertEquals(1, docTimestampsCounter);
		assertEquals(0, archiveTimestampsCounter);
	}
	
	@Override
	protected void validateETSISignatureIdentifier(SignatureIdentifierType signatureIdentifier) {
		super.validateETSISignatureIdentifier(signatureIdentifier);
		
		assertNotNull(signatureIdentifier);
		assertFalse(signatureIdentifier.isDocHashOnly());
		assertFalse(signatureIdentifier.isHashOnly());
		
		assertNotNull(signatureIdentifier.getSignatureValue());
	}
	
	@Override
	protected void checkPdfRevision(DiagnosticData diagnosticData) {
		super.checkPdfRevision(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals("ПОДПИСАН ОТ", signature.getReason());
	}

	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);

		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());

		boolean sigTstFound = false;
		boolean arcTstFound = false;
		for (TimestampWrapper timestampWrapper : timestampList) {
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
				sigTstFound = true;
			} else if (TimestampType.DOCUMENT_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertEquals(ArchiveTimestampType.PAdES, timestampWrapper.getArchiveTimestampType());
				assertEquals(1, timestampWrapper.getTimestampedSignatures().size());
				assertEquals(1, timestampWrapper.getTimestampedTimestamps().size());
				assertEquals(1, timestampWrapper.getTimestampedRevocations().size());
				arcTstFound = true;
			}
		}
		assertTrue(sigTstFound);
		assertTrue(arcTstFound);
	}

}
