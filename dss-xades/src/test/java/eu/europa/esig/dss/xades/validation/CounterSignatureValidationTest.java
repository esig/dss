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
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.validationreport.jaxb.SACounterSignatureType;
import eu.europa.esig.validationreport.jaxb.SignatureAttributesType;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import jakarta.xml.bind.JAXBElement;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CounterSignatureValidationTest extends AbstractXAdESTestValidation {
	
	private String ddCounterSignatureId = null;

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/TEST_S1a_C1a_InTL_VALID.xml");
	}
	
	@Override
	protected void checkCounterSignatures(DiagnosticData diagnosticData) {
		super.checkCounterSignatures(diagnosticData);
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		int countSignatures = 0;
		int countCounterSignatures = 0;

		for (SignatureWrapper signatureWrapper : signatures) {
			if (signatureWrapper.isCounterSignature()) {
				ddCounterSignatureId = signatureWrapper.getId();
				countCounterSignatures++;
			} else {
				countSignatures++;
			}
			assertNotNull(signatureWrapper.getSignatureFilename());
		}
		assertEquals(1, countSignatures);
		assertEquals(1, countCounterSignatures);
		
		assertNotNull(ddCounterSignatureId);
	}
	
	@Override
	protected void verifyETSIValidationReport(ValidationReportType etsiValidationReportJaxb) {
		super.verifyETSIValidationReport(etsiValidationReportJaxb);

		int countSignatures = 0;
		int countCounterSignatures = 0;
		
		String etsiCounterSignatureId = null;

		List<SignatureValidationReportType> reports = etsiValidationReportJaxb.getSignatureValidationReport();
		for (SignatureValidationReportType signatureValidationReport : reports) {
			boolean containsCounterSignatures = false;

			SignatureAttributesType signatureAttributes = signatureValidationReport.getSignatureAttributes();
			List<JAXBElement<?>> signatureAttributeObjects = signatureAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat();
			for (JAXBElement<?> signatureAttributeObj : signatureAttributeObjects) {
				Object value = signatureAttributeObj.getValue();
				if (value instanceof SACounterSignatureType) {
					SACounterSignatureType counterSignatureType = (SACounterSignatureType) signatureAttributeObj.getValue();
					assertNotNull(counterSignatureType.getAttributeObject());
					assertEquals(1, counterSignatureType.getAttributeObject().size());
					assertTrue(Utils.isCollectionNotEmpty(counterSignatureType.getAttributeObject()));
					assertNotNull(counterSignatureType.getCounterSignature());
					SignatureIdentifierType counterSignatureReference = (SignatureIdentifierType) counterSignatureType.getAttributeObject().get(0).getVOReference().get(0);
					etsiCounterSignatureId = counterSignatureReference.getId();
					countCounterSignatures++;
					containsCounterSignatures = true;
				}
			}
			if (!containsCounterSignatures) {
				countSignatures++;
			}
		}
		
		assertEquals(1, countSignatures);
		assertEquals(1, countCounterSignatures);
		assertNotNull(etsiCounterSignatureId);
		
		assertEquals(ddCounterSignatureId, etsiCounterSignatureId);
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		// counter signature reference fails
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		// no original documents
	}

}
