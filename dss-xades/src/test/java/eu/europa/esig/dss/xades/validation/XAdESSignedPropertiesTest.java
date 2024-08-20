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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.List;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.xades.jaxb.xades132.DigestAlgAndValueType;

class XAdESSignedPropertiesTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss-signed.xml");
	}

	@Override
	protected void checkDigestMatchers(DiagnosticData diagnosticData) {
		super.checkDigestMatchers(diagnosticData);
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		SignatureWrapper signatureWrapper = signatures.get(0);
		List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
		XmlDigestMatcher signedPropertiesDigest = null;
		XmlDigestMatcher refDigest = null;

		for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
			if (DigestMatcherType.SIGNED_PROPERTIES == xmlDigestMatcher.getType()) {
				signedPropertiesDigest = xmlDigestMatcher;
			} else if (DigestMatcherType.REFERENCE == xmlDigestMatcher.getType()) {
				refDigest = xmlDigestMatcher;
			} else {
				fail("Unexpected " + xmlDigestMatcher.getType());
			}
		}

		assertNotNull(signedPropertiesDigest);
		assertTrue(signedPropertiesDigest.isDataFound());
		assertTrue(signedPropertiesDigest.isDataIntact());
		assertNotNull(refDigest);
		assertTrue(refDigest.isDataFound());
		assertTrue(refDigest.isDataIntact());
	}
	
	@Override
	protected void verifyDetailedReport(DetailedReport detailedReport) {
		super.verifyDetailedReport(detailedReport);

		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND,
				detailedReport.getBasicBuildingBlocksSubIndication(detailedReport.getFirstSignatureId()));
	}
	
	@Override
	protected void checkSignatureReports(Reports reports) {
		super.checkSignatureReports(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
		assertNotNull(digestMatchers);
		assertTrue(digestMatchers.size() > 1);
		
		ValidationReportType etsiValidationReportJaxb = reports.getEtsiValidationReportJaxb();
		List<SignatureValidationReportType> signatureValidationReport = etsiValidationReportJaxb.getSignatureValidationReport();
		assertTrue(Utils.isCollectionNotEmpty(signatureValidationReport));
		assertEquals(1, signatureValidationReport.size());
		SignatureValidationReportType signatureValidationReportType = signatureValidationReport.get(0);
		
		XmlDigestAlgoAndValue dataToBeSignedRepresentation = signatureWrapper.getDataToBeSignedRepresentation();
		
		SignatureIdentifierType signatureIdentifier = signatureValidationReportType.getSignatureIdentifier();
		assertNotNull(signatureIdentifier);
		assertEquals(signatureWrapper.getId(), signatureIdentifier.getId());
		
		DigestAlgAndValueType digestAlgAndValue = signatureIdentifier.getDigestAlgAndValue();
		assertNotNull(digestAlgAndValue);
		assertEquals(dataToBeSignedRepresentation.getDigestMethod(), DigestAlgorithm.forXML(digestAlgAndValue.getDigestMethod().getAlgorithm()));
		assertArrayEquals(dataToBeSignedRepresentation.getDigestValue(), digestAlgAndValue.getDigestValue());
	}

}
