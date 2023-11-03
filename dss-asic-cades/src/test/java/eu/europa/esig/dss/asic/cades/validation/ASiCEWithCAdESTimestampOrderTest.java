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
package eu.europa.esig.dss.asic.cades.validation;


import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.POEType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEWithCAdESTimestampOrderTest extends AbstractASiCWithCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss1984.asice");
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		assertEquals(TimestampType.SIGNATURE_TIMESTAMP, timestampList.get(0).getType());
		assertEquals(TimestampType.CONTAINER_TIMESTAMP, timestampList.get(1).getType());
	}
	
	@Override
	protected void checkReportsTokens(Reports reports) {
		super.checkReportsTokens(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		
		TimestampWrapper signatureTimestamp = timestampList.get(0);
		List<String> coveredIds = signatureTimestamp.getTimestampedObjects().stream().map(obj -> obj.getToken().getId()).collect(Collectors.toList());
		int coveredData = signatureTimestamp.getTimestampedCertificates().size() + signatureTimestamp.getTimestampedSignedData().size();
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReport);
		assertNotNull(etsiValidationReport.getSignatureValidationObjects());
		assertNotNull(etsiValidationReport.getSignatureValidationObjects().getValidationObject());
		
		int timestampedDataCounter = 0;
		for (ValidationObjectType validationObject : etsiValidationReport.getSignatureValidationObjects().getValidationObject()) {
			if (coveredIds.contains(validationObject.getId())) {
				POEType poe = validationObject.getPOE();
				assertNotNull(poe);
				assertNotNull(poe.getTypeOfProof());
				assertEquals(signatureTimestamp.getProductionTime(), poe.getPOETime());
				assertNotNull(poe.getPOEObject());
				assertNotNull(poe.getPOEObject().getVOReference());
				assertEquals(1, poe.getPOEObject().getVOReference().size());
				Object poeObject = poe.getPOEObject().getVOReference().get(0);
				assertTrue(poeObject instanceof ValidationObjectType);
				assertEquals(signatureTimestamp.getId(), ((ValidationObjectType) poeObject).getId());
				
				++timestampedDataCounter;
			}
		}
		assertEquals(coveredData, timestampedDataCounter);
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

}
