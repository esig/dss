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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationRefWrappper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAbstractToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
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
		List<RelatedRevocationWrapper> foundRevocations = signature.foundRevocations().getRelatedRevocationData();
		assertNotNull(foundRevocations);
		assertEquals(1, foundRevocations.size());
		List<RelatedRevocationWrapper> timestampRevocationValues = signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES);
		assertNotNull(timestampRevocationValues);
		assertEquals(1, timestampRevocationValues.size());
		List<RelatedRevocationWrapper> timestampRevocationRefs = signature.foundRevocations()
				.getRelatedRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
		assertNotNull(timestampRevocationRefs);
		assertEquals(1, timestampRevocationRefs.size());
		
		List<TimestampWrapper> timestamps = diagnosticData.getTimestampList();
		assertTrue(Utils.isCollectionNotEmpty(timestamps));
		int signatureTimestampCounter = 0;
		int archiveTimestampCounter = 0;
		for (TimestampWrapper timestamp : timestamps) {
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
				assertEquals(11, timestamp.getTimestampedObjects().size());
				archiveTimestampCounter++;
			} else if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestamp.getType())) {
				assertEquals(3, timestamp.getTimestampedObjects().size());
				List<RelatedRevocationWrapper> timestampFoundRevocations = timestamp.foundRevocations().getRelatedRevocationData();
				assertEquals(1, timestampFoundRevocations.size());
				RelatedRevocationWrapper xmlFoundRevocation = timestampFoundRevocations.get(0);
				assertTrue(xmlFoundRevocation.getOrigins().contains(RevocationOrigin.REVOCATION_VALUES));
				List<RevocationRefWrappper> revocationRefs = xmlFoundRevocation.getReferences();
				assertEquals(1, revocationRefs.size());
				RevocationRefWrappper xmlRevocationRef = revocationRefs.get(0);
				assertTrue(xmlRevocationRef.getOrigins().contains(RevocationRefOrigin.COMPLETE_REVOCATION_REFS));
				signatureTimestampCounter++;
			}
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
		}
		assertEquals(1, signatureTimestampCounter);
		assertEquals(1, archiveTimestampCounter);
		
	}

	@Test
	public void dss1469testExpired() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1469/cadesLTAwithATv2expired.p7s");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		CertificateToken tstCaCert = DSSUtils.loadCertificateFromBase64EncodedString("MIID9TCCAt2gAwIBAgIQF3Dg4iQuLQxzMPFRPs8rqDANBgkqhkiG9w0BAQsFADByMSMwIQYDVQQDExpVbml2ZXJzaWduIFRpbWVzdGFtcGluZyBDQTEcMBoGA1UECxMTMDAwMiA0MzkxMjkxNjQwMDAyNjEgMB4GA1UEChMXQ3J5cHRvbG9nIEludGVybmF0aW9uYWwxCzAJBgNVBAYTAkZSMB4XDTEwMDUwNjA5MzA1OVoXDTIwMDUwNjA5MzA1OVowcjEjMCEGA1UEAxMaVW5pdmVyc2lnbiBUaW1lc3RhbXBpbmcgQ0ExHDAaBgNVBAsTEzAwMDIgNDM5MTI5MTY0MDAwMjYxIDAeBgNVBAoTF0NyeXB0b2xvZyBJbnRlcm5hdGlvbmFsMQswCQYDVQQGEwJGUjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMF2r8Q+dqh3iA6fPMn0bOw50sKTsCPCocGVNPf75b6dERmkuiXj48/M6poFaPxV96Y01B8LjTUFYGQr6Vbf/15HvVskV6ZSTb8PXNZef6vv7681qnMp7NZVyrWO9zjg4NcZ9qVKFlzZe2NCGHAZi+5z7Y4Phnvg7XdLu0B92oERAIoconTcsHO6BSg9nhv0c+xDsUNdRKF1groYZtAwNO1L1j5kLY3PukPPKa0+uyrJ8j56mGGUGWKaZxLuKafn5M3tYMousgKxQ/5cDHnjntTFBXfm7+Jg0PeiJP6boM2nZDTcnPBt+wvXzo27L4GV0GvZfoi0CVa27hkURRSnsJcCAwEAAaOBhjCBgzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjBBBgNVHSAEOjA4MDYGCisGAQQB+0sFAQEwKDAmBggrBgEFBQcCARYaaHR0cDovL2RvY3MudW5pdmVyc2lnbi5ldS8wHQYDVR0OBBYEFOzknxQd8GYKOfVELMDFf8PMwaW1MA0GCSqGSIb3DQEBCwUAA4IBAQAySgYJxVNszlupDmOTfKcSXRohKwxfgv/wVJhH7ypgqX9z+KM8sh0FDrO2TbEyU/rnpJwauTUwPoa40plvLcBV3zcsA72mzG9fgjmftj0D5Lxhkqsn7B13YOP/tlqoe4f1jyfysxc/JpoBKXklJIBMW5DAbPxZPehVRpBJqrd0ZJNhKZFbBZvVIZ7KO5PX10k1016yiB8LIuASeJfGMHlzvX0qorvl+98g868vQQB6xyMC8WcikEVsVrTBXnNsdD2F6EkC+HJ88qT5XfUGMxq88hvufpwfD3kTkqDm5RDhn0a0o8eIRlze2XopYWz17GWyUVyawoZcEfFYlDxjbo1p");
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		CommonCertificateSource certificateSource = new CommonCertificateSource();
		certificateSource.addCertificate(tstCaCert);
		certificateVerifier.setAdjunctCertSource(certificateSource);
		validator.setCertificateVerifier(certificateVerifier);
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		List<RelatedRevocationWrapper> foundRevocations = signature.foundRevocations().getRelatedRevocationData();
		assertNotNull(foundRevocations);
		assertEquals(2, foundRevocations.size());
		
		List<String> revocationIds = new ArrayList<>();
		for (RevocationWrapper revocationWrapper : diagnosticData.getAllRevocationData()) {
			revocationIds.add(revocationWrapper.getId());
		}
		assertEquals(3, revocationIds.size());
		
		List<TimestampWrapper> timestamps = diagnosticData.getTimestampList();
		assertTrue(Utils.isCollectionNotEmpty(timestamps));
		int signatureTimestampCounter = 0;
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
			} else if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestamp.getType())) {
				List<RelatedRevocationWrapper> allFoundRevocations = timestamp.foundRevocations().getRelatedRevocationData();
				assertEquals(1, allFoundRevocations.size());
				signatureTimestampCounter++;
			}
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
		}
		assertEquals(1, signatureTimestampCounter);
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
