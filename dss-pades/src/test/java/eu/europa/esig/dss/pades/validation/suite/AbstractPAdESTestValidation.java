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
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlByteRange;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.test.validation.AbstractDocumentTestValidation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SAContactInfoType;
import eu.europa.esig.validationreport.jaxb.SADSSType;
import eu.europa.esig.validationreport.jaxb.SAFilterType;
import eu.europa.esig.validationreport.jaxb.SANameType;
import eu.europa.esig.validationreport.jaxb.SAReasonType;
import eu.europa.esig.validationreport.jaxb.SASubFilterType;
import eu.europa.esig.validationreport.jaxb.SAVRIType;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractPAdESTestValidation extends AbstractDocumentTestValidation<PAdESSignatureParameters, PAdESTimestampParameters> {
	
	@Override
	protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			assertNotNull(signature.getSignatureValue());
		}
	}
	
	@Override
	protected void checkDigestAlgorithm(DiagnosticData diagnosticData) {
		super.checkDigestAlgorithm(diagnosticData);
		
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertEquals(1, signatureWrapper.getDigestMatchers().size());
		}
	}

	@Override
	protected void checkReportsSignatureIdentifier(Reports reports) {
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		
		if (Utils.isCollectionNotEmpty(diagnosticData.getSignatures())) {
			for (SignatureValidationReportType signatureValidationReport : etsiValidationReport.getSignatureValidationReport()) {
				SignatureWrapper signature = diagnosticData.getSignatureById(signatureValidationReport.getSignatureIdentifier().getId());
				
				SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
				assertNotNull(signatureIdentifier);
				
				assertNotNull(signatureIdentifier.getSignatureValue());
                assertArrayEquals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue());
			}
		}
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);

		for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
			if (TimestampType.DOCUMENT_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertEquals(1, timestampWrapper.getTimestampScopes().size());
			}
		}
	}

	@Override
	protected void checkPdfRevision(DiagnosticData diagnosticData) {
		super.checkPdfRevision(diagnosticData);
		
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			XmlPDFRevision pdfRevision = signatureWrapper.getPDFRevision();
			assertNotNull(pdfRevision);
			assertTrue(Utils.isCollectionNotEmpty(pdfRevision.getFields()));
			checkPdfSignatureDictionary(pdfRevision.getPDFSignatureDictionary());

			assertFalse(signatureWrapper.arePdfModificationsDetected());
			assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfUndefinedChanges()));
		}
		
		for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
			if (TimestampType.DOCUMENT_TIMESTAMP.equals(timestampWrapper.getType())) {
				XmlPDFRevision pdfRevision = timestampWrapper.getPDFRevision();
				assertNotNull(pdfRevision);
				assertTrue(Utils.isCollectionNotEmpty(pdfRevision.getFields()));
				checkPdfSignatureDictionary(pdfRevision.getPDFSignatureDictionary());

				assertFalse(timestampWrapper.arePdfModificationsDetected());
				assertTrue(Utils.isCollectionEmpty(timestampWrapper.getPdfUndefinedChanges()));
			}
		}
	}

	protected void checkPdfSignatureDictionary(XmlPDFSignatureDictionary pdfSignatureDictionary) {
		assertNotNull(pdfSignatureDictionary);
		assertNotNull(pdfSignatureDictionary.getType());
		assertNotNull(pdfSignatureDictionary.getSubFilter());
		checkByteRange(pdfSignatureDictionary.getSignatureByteRange());
		assertTrue(pdfSignatureDictionary.isConsistent());
	}

	protected void checkByteRange(XmlByteRange byteRange) {
		assertNotNull(byteRange);
		assertEquals(4, byteRange.getValue().size());
		assertTrue(byteRange.isValid());
	}
	
	@Override
	protected void validateETSIDSSType(SADSSType dss) {
		// do nothing
	}
	
	@Override
	protected void validateETSIVRIType(SAVRIType vri) {
		// do nothing
	}
	
	@Override
	protected void validateETSISAReasonType(SAReasonType reasonType) {
		// do nothing
	}
	
	@Override
	protected void validateETSISAName(SANameType nameType) {
		// do nothing
	}
	
	@Override
	protected void validateETSIContactInfo(SAContactInfoType contactTypeInfo) {
		// do nothing
	}
	
	@Override
	protected void validateETSIFilter(SAFilterType filterType) {
		assertNotNull(filterType);
	}
	
	@Override
	protected void validateETSISubFilter(SASubFilterType subFilterType) {
		assertNotNull(subFilterType);
	}

}
