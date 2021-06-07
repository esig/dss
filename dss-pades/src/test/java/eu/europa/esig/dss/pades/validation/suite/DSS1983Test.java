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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectListType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS1983Test extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/DSS-1983.pdf"));
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		
		TimestampWrapper signatureTimestamp = timestampList.get(0);
		assertEquals(TimestampType.SIGNATURE_TIMESTAMP, signatureTimestamp.getType());
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		super.verifyOriginalDocuments(validator, diagnosticData);
		
		assertEquals(1, diagnosticData.getOriginalSignerDocuments().size());
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void verifyReportsData(Reports reports) {
		super.verifyReportsData(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		TimestampWrapper signatureTimestamp = timestampList.get(0);
		
		ValidationReportType etsiValidationReportJaxb = reports.getEtsiValidationReportJaxb();
		ValidationObjectListType signatureValidationObjects = etsiValidationReportJaxb.getSignatureValidationObjects();
		assertNotNull(signatureValidationObjects);
		
		int signedDataCounter = 0;
		for (ValidationObjectType validationObject : signatureValidationObjects.getValidationObject()) {
			if (ObjectType.SIGNED_DATA.equals(validationObject.getObjectType())) {
				List<SignerDataWrapper> timestampedSignedData = signatureTimestamp.getTimestampedSignedData();
				assertNotNull(timestampedSignedData);
				List<String> timestampedSignedDataIds = timestampedSignedData.stream().map(SignerDataWrapper::getId).collect(Collectors.toList());
				assertTrue(timestampedSignedDataIds.contains(validationObject.getId()));
				assertNotNull(validationObject.getPOE());
				assertNotNull(validationObject.getPOE().getPOEObject());
				assertEquals(1, validationObject.getPOE().getPOEObject().getVOReference().size());
				Object poeObject = validationObject.getPOE().getPOEObject().getVOReference().get(0);
				assertTrue(poeObject instanceof ValidationObjectType);
				assertEquals(signatureTimestamp.getId(), ((ValidationObjectType) poeObject).getId());
				++signedDataCounter;
			}
		}
		assertEquals(1, signedDataCounter);
	}

	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(1, diagnosticData.getAllOrphanCertificateObjects().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationObjects().size());
	}

}
