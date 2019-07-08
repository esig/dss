package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.jaxb.diagnostic.XmlAbstractToken;
import eu.europa.esig.dss.jaxb.diagnostic.XmlFoundRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocationRef;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestamp;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedObject;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.XmlRevocationOrigin;
import eu.europa.esig.dss.validation.XmlRevocationRefOrigin;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.x509.TimestampType;

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
		List<String> timestampRevocationValues = signature.getRevocationIdsByOrigin(XmlRevocationOrigin.TIMESTAMP_REVOCATION_VALUES);
		assertNotNull(timestampRevocationValues);
		assertEquals(1, timestampRevocationValues.size());
		List<XmlRevocationRef> timestampRevocationRefs = signature.getFoundRevocationRefsByOrigin(XmlRevocationRefOrigin.TIMESTAMP_REVOCATION_REFS);
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
