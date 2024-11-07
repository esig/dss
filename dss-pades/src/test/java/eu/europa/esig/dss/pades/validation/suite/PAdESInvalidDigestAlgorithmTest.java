/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.validationreport.jaxb.CryptoInformationType;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.ValidationReportDataType;
import eu.europa.esig.validationreport.jaxb.ValidationTimeInfoType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESInvalidDigestAlgorithmTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/Signature-P-HU_NET-2.pdf"));
	}
	
	@Override
	protected void checkDigestAlgorithm(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNull(signatureWrapper.getDigestAlgorithm());
	}
	
	@Override
	protected void checkMessageDigestAlgorithm(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
		assertEquals(1, digestMatchers.size());
		XmlDigestMatcher xmlDigestMatcher = digestMatchers.get(0);
		assertNull(xmlDigestMatcher.getDigestMethod());
		assertNotNull(xmlDigestMatcher.getDigestValue());
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signatureWrapper.isBLevelTechnicallyValid());
		assertNotNull(signatureWrapper.getEncryptionAlgorithm());
		assertNotNull(signatureWrapper.getKeyLengthUsedToSignThisToken());
		assertFalse(signatureWrapper.isSignatureIntact());
		assertFalse(signatureWrapper.isSignatureValid());
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signatureWrapper.getSigningCertificate());
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkDTBSR(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNull(signatureWrapper.getDataToBeSignedRepresentation()); // DigestAlgo is not supported
	}
	
	@Override
	protected void validateETSISignatureIdentifier(SignatureIdentifierType signatureIdentifier) {
		assertNotNull(signatureIdentifier);
		assertNotNull(signatureIdentifier.getId());
		assertNull(signatureIdentifier.getDigestAlgAndValue());
		assertNotNull(signatureIdentifier.getSignatureValue());
	}

	@Override
	protected void validateAssociatedValidationReportData(ValidationTimeInfoType validationTimeInfo,
														  List<ValidationReportDataType> associatedValidationReportData) {
		super.validateAssociatedValidationReportData(validationTimeInfo, associatedValidationReportData);

		assertEquals(1, associatedValidationReportData.size());
		ValidationReportDataType validationReport = associatedValidationReportData.get(0);
		CryptoInformationType cryptoInformation = validationReport.getCryptoInformation();
		assertNotNull(cryptoInformation);
		assertNotNull(cryptoInformation.getValidationObjectId());
		assertEquals("urn:etsi:019102:algorithm:unidentified", cryptoInformation.getAlgorithm());
		assertNull(cryptoInformation.getNotAfter());
		assertFalse(cryptoInformation.isSecureAlgorithm());
	}
}
