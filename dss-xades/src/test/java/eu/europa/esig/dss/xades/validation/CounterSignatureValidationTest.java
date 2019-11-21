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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import javax.xml.bind.JAXBElement;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.DefaultDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SACounterSignatureType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

public class CounterSignatureValidationTest {

	@Test
	public void test() {

		DSSDocument doc = new FileDocument("src/test/resources/validation/TEST_S1a_C1a_InTL_VALID.xml");

		DefaultDocumentValidator sdv = DefaultDocumentValidator.fromDocument(doc);
		sdv.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = sdv.validateDocument();

		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		int countSignatures = 0;
		int countCounterSignatures = 0;
		String ddCounterSignatureId = null; 

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
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();

		countSignatures = 0;
		countCounterSignatures = 0;
		String etsiCounterSignatureId = null; 
		
		List<SignatureValidationReportType> signatureValidationReports = etsiValidationReport.getSignatureValidationReport();
		for (SignatureValidationReportType signatureValidationReport : signatureValidationReports) {
			List<Object> signingTimeOrSigningCertificateOrDataObjectFormat = signatureValidationReport.getSignatureAttributes()
					.getSigningTimeOrSigningCertificateOrDataObjectFormat();
			boolean containsCounterSignatures = false;
			for (Object object : signingTimeOrSigningCertificateOrDataObjectFormat) {
				JAXBElement<?> jaxbElement = (JAXBElement<?>) object;
				if (jaxbElement.getValue() instanceof SACounterSignatureType) {
					SACounterSignatureType counterSignatureType = (SACounterSignatureType) jaxbElement.getValue();
					assertNotNull(counterSignatureType.getAttributeObject());
					assertEquals(1, counterSignatureType.getAttributeObject().size());
					assertTrue(Utils.isCollectionNotEmpty(counterSignatureType.getAttributeObject()));
					assertNotNull(counterSignatureType.getCounterSignature());
					ValidationObjectType counterSignatureReference = (ValidationObjectType) counterSignatureType.getAttributeObject().get(0).getVOReference().get(0);
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
		assertNotNull(ddCounterSignatureId);
		assertNotNull(etsiCounterSignatureId);
		assertEquals(ddCounterSignatureId, etsiCounterSignatureId);
		
	}

}
