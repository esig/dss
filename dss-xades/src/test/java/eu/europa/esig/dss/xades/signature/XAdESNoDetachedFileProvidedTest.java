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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESNoDetachedFileProvidedTest extends PKIFactoryAccess {
	
	@Test
	void bLevelTest() {
		
		DSSDocument document = new FileDocument("src/test/resources/validation/dss2011/xades-detached.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signature.isBLevelTechnicallyValid());
		assertFalse(signature.isSignatureIntact());
		assertFalse(signature.isSignatureValid());
		
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		int references = 0;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if (DigestMatcherType.REFERENCE.equals(digestMatcher.getType())) {
				assertFalse(digestMatcher.isDataFound());
				assertFalse(digestMatcher.isDataIntact());
				++references;
			}
		}
		assertEquals(1, references);
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
	}
	
	@Test
	void ltaLevelTest() {

		DSSDocument document = new FileDocument("src/test/resources/validation/dss2011/xades-lta-detached.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signature.isBLevelTechnicallyValid());
		assertFalse(signature.isSignatureIntact());
		assertFalse(signature.isSignatureValid());
		
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		int references = 0;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if (DigestMatcherType.REFERENCE.equals(digestMatcher.getType())) {
				assertFalse(digestMatcher.isDataFound());
				assertFalse(digestMatcher.isDataIntact());
				++references;
			}
		}
		assertEquals(1, references);
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		String archiveTstId = null;
		for (TimestampWrapper timestamp : timestampList) {
			if (timestamp.getType().isArchivalTimestamp()) {
				assertNull(archiveTstId);
				assertFalse(timestamp.isMessageImprintDataFound());
				assertFalse(timestamp.isMessageImprintDataIntact());
				assertTrue(timestamp.isSignatureIntact());
				assertFalse(timestamp.isSignatureValid());
				
				archiveTstId = timestamp.getId();
			}
		}
		assertNotNull(archiveTstId);
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks archiveTstBBB = detailedReport.getBasicBuildingBlockById(archiveTstId);
		assertNotNull(archiveTstBBB);
		assertEquals(Indication.INDETERMINATE, archiveTstBBB.getConclusion().getIndication());
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, archiveTstBBB.getConclusion().getSubIndication());
		
	}
	
	@Test
	void individualContentTstTest() {

		DSSDocument document = new FileDocument("src/test/resources/validation/dss2011/xades-individual-content-tst-detached.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signature.isBLevelTechnicallyValid());
		assertFalse(signature.isSignatureIntact());
		assertFalse(signature.isSignatureValid());
		
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		int objects = 0;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if (DigestMatcherType.OBJECT.equals(digestMatcher.getType())) {
				assertFalse(digestMatcher.isDataFound());
				assertFalse(digestMatcher.isDataIntact());
				++objects;
			}
		}
		assertEquals(1, objects);
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(1, timestampList.size());
		
		TimestampWrapper timestamp = timestampList.get(0);
		assertEquals(TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP, timestamp.getType());
		
		assertFalse(timestamp.isMessageImprintDataFound());
		assertFalse(timestamp.isMessageImprintDataIntact());
		assertTrue(timestamp.isSignatureIntact());
		assertFalse(timestamp.isSignatureValid());
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(timestamp.getId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, detailedReport.getBasicTimestampValidationSubIndication(timestamp.getId()));
		
	}
	
	@Test
	void allDataContentTstTest() {

		DSSDocument document = new FileDocument("src/test/resources/validation/dss2011/xades-alldata-tst-detached.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		// only one detached file is provided
		validator.setDetachedContents(Collections.singletonList(new FileDocument("src/test/resources/sample.png")));
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signature.isBLevelTechnicallyValid());
		assertFalse(signature.isSignatureIntact());
		assertFalse(signature.isSignatureValid());
		
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		int references = 0;
		boolean oneFoundValid = false;
		boolean oneNotFoundInvalid = false;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if (DigestMatcherType.REFERENCE.equals(digestMatcher.getType())) {
				if (digestMatcher.isDataFound() && digestMatcher.isDataIntact()) {
					oneFoundValid = true;
				} else if (!digestMatcher.isDataFound() && !digestMatcher.isDataIntact()) {
					oneNotFoundInvalid = true;
				}
				++references;
			}
		}
		assertTrue(oneFoundValid);
		assertTrue(oneNotFoundInvalid);
		assertEquals(2, references);
		
		DetailedReport detailedReport = reports.getDetailedReport();

		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		for (TimestampWrapper timestamp : timestampList) {
			assertEquals(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP, timestamp.getType());
			
			assertFalse(timestamp.isMessageImprintDataFound());
			assertFalse(timestamp.isMessageImprintDataIntact());
			assertTrue(timestamp.isSignatureIntact());
			assertFalse(timestamp.isSignatureValid());
			
			XmlBasicBuildingBlocks contentTstBBB = detailedReport.getBasicBuildingBlockById(timestamp.getId());
			assertNotNull(contentTstBBB);
			assertEquals(Indication.INDETERMINATE, contentTstBBB.getConclusion().getIndication());
			assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, contentTstBBB.getConclusion().getSubIndication());
		}
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
