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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureAttributesType;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XMLDSigOnlyValidationTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/xmldsig-only.xml");
	}

	@Override
	protected void checkDigestMatchers(DiagnosticData diagnosticData) {
		super.checkDigestMatchers(diagnosticData);

		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(SignatureLevel.XML_NOT_ETSI, signatureWrapper.getSignatureFormat());
		List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
		assertEquals(1, digestMatchers.size());
		for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
			assertTrue(xmlDigestMatcher.isDataFound());
			assertTrue(xmlDigestMatcher.isDataIntact());
		}
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureWrapper.isSignatureIntact());
		assertTrue(signatureWrapper.isSignatureValid());
		assertFalse(signatureWrapper.isSigningCertificateReferencePresent());
		assertNull(signatureWrapper.getSigningCertificateReference());
	}
	
	@Override
	protected void checkSigningDate(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNull(signatureWrapper.getClaimedSigningTime());
	}
	
	@Override
	protected void validateSignerInformation(SignerInformationType signerInformation) {
		assertNull(signerInformation);
	}

	@Override
	protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signatureWrapper.getSignatureValue());
		assertNull(signatureWrapper.getDAIdentifier());
	}
	
	@Override
	protected void checkReportsSignatureIdentifier(Reports reports) {
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		List<SignatureValidationReportType> signatureValidationReport = etsiValidationReport.getSignatureValidationReport();
		assertEquals(1, signatureValidationReport.size());
		SignatureValidationReportType signatureValidationReportType = signatureValidationReport.get(0);
		SignatureIdentifierType signatureIdentifier = signatureValidationReportType.getSignatureIdentifier();

		assertNotNull(signatureIdentifier.getSignatureValue());
		assertNull(signatureIdentifier.getDAIdentifier());
	}

	@Override
	protected void validateETSISignatureAttributes(SignatureAttributesType signatureAttributes) {
		assertNull(signatureAttributes);
	}

}
