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
package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAbstractToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocationRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class CAdESLTALevelExtendedTest {
	
	@Test
	public void dss1469test() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1469/cadesLTAwithATv2.sig");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		DSSDocument detachedContent = new FileDocument("src/test/resources/validation/dss-1469/screenshot2.png");
		validator.setDetachedContents(Arrays.asList(detachedContent));
		Reports reports = validator.validateDocument();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		List<XmlFoundRevocation> foundRevocations = signature.getAllFoundRevocations();
		assertNotNull(foundRevocations);
		assertEquals(2, foundRevocations.size());
		List<String> timestampRevocationValues = signature.getRevocationIdsByOrigin(RevocationOrigin.TIMESTAMP_REVOCATION_VALUES);
		assertNotNull(timestampRevocationValues);
		assertEquals(1, timestampRevocationValues.size());
		List<XmlRevocationRef> timestampRevocationRefs = signature.getFoundRevocationRefsByOrigin(RevocationRefOrigin.TIMESTAMP_REVOCATION_REFS);
		assertNotNull(timestampRevocationRefs);
		assertEquals(1, timestampRevocationRefs.size());
		
		List<TimestampWrapper> timestamps = diagnosticData.getTimestampList();
		assertTrue(Utils.isCollectionNotEmpty(timestamps));
		int archiveTimestampCounter = 0;
		for (TimestampWrapper timestamp : timestamps) {
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
				assertEquals(11, timestamp.getTimestampedObjects().size());
				archiveTimestampCounter++;
			}
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
		}
		assertEquals(1, archiveTimestampCounter);
		
	}

	@Test
	public void dss1469testExpired() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1469/cadesLTAwithATv2expired.p7s");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		List<XmlFoundRevocation> foundRevocations = signature.getAllFoundRevocations();
		assertNotNull(foundRevocations);
		assertEquals(3, foundRevocations.size());
		
		List<String> revocationIds = signature.getRevocationIds();
		assertEquals(3, revocationIds.size());
		
		List<TimestampWrapper> timestamps = diagnosticData.getTimestampList();
		assertTrue(Utils.isCollectionNotEmpty(timestamps));
		int archiveTimestampCounter = 0;
		for (TimestampWrapper timestamp : timestamps) {
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
				int foundRevocationsCounter = 0;
				List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
				for (XmlTimestampedObject timestampedObject : timestampedObjects) {
					if (revocationIds.contains(timestampedObject.getToken().getId())) {
						foundRevocationsCounter++;
					}
				}
				assertEquals(3, foundRevocationsCounter);
				archiveTimestampCounter++;
			}
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
		}
		assertEquals(1, archiveTimestampCounter);
	}
	
	@Test
	public void dss1670test() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1670/signatureExtendedTwoLTA.p7s");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		DSSDocument detachedContent = new FileDocument("src/test/resources/validation/dss-1670/screenshot.png");
		validator.setDetachedContents(Arrays.asList(detachedContent));
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		List<TimestampWrapper> timestampList = signature.getTimestampList();
		assertNotNull(timestampList);
		assertEquals(3, timestampList.size());
		
		int timestamedTimestampsCounter = 0;
		for (TimestampWrapper timestamp : timestampList) {
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
			
			List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
			assertNotNull(timestampedObjects);
			assertTrue(timestampedObjects.size() > 0);
			
			for (XmlTimestampedObject timestampedObject : timestampedObjects) {
				XmlAbstractToken token = timestampedObject.getToken();
				if (token instanceof XmlTimestamp) {
					XmlTimestamp timestampedTimestamp = (XmlTimestamp) token;
					assertNotNull(timestampedTimestamp);
					assertTrue(timestampedTimestamp.getProductionTime().before(timestamp.getProductionTime()));
					timestamedTimestampsCounter++;
				}
			}
		}
		assertEquals(3, timestamedTimestampsCounter);
	}

}
