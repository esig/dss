package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

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

/*
 * DSS-2011
 */
public class CAdESNoDetachedFileProvidedTest extends PKIFactoryAccess {
	
	@Test
	public void bLevelTest() {
		
		DSSDocument document = new FileDocument("src/test/resources/validation/dss-2011/cades-detached.pkcs7");
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
		int messageDigests = 0;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if (DigestMatcherType.MESSAGE_DIGEST.equals(digestMatcher.getType())) {
				assertFalse(digestMatcher.isDataFound());
				assertFalse(digestMatcher.isDataIntact());
				++messageDigests;
			}
		}
		assertEquals(1, messageDigests);
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
	}
	
	@Test
	public void ltaLevelTest() {
		
		DSSDocument document = new FileDocument("src/test/resources/validation/dss-2011/cades-lta-detached.pkcs7");
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
		int messageDigests = 0;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if (DigestMatcherType.MESSAGE_DIGEST.equals(digestMatcher.getType())) {
				assertFalse(digestMatcher.isDataFound());
				assertFalse(digestMatcher.isDataIntact());
				++messageDigests;
			}
		}
		assertEquals(1, messageDigests);
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		String archiveTstId = null;
		for (TimestampWrapper timestamp : timestampList) {
			if (timestamp.getType().isArchivalTimestamp()) {
				assertNull(archiveTstId);
				assertFalse(timestamp.isMessageImprintDataFound());
				assertFalse(timestamp.isMessageImprintDataIntact());
				assertTrue(timestamp.isSignatureIntact());
				assertTrue(timestamp.isSignatureValid());
				
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
	public void contentTstTest() {
		
		DSSDocument document = new FileDocument("src/test/resources/validation/dss-2011/cades-content-tst.pkcs7");
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
		int messageDigests = 0;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if (DigestMatcherType.MESSAGE_DIGEST.equals(digestMatcher.getType())) {
				assertFalse(digestMatcher.isDataFound());
				assertFalse(digestMatcher.isDataIntact());
				++messageDigests;
			}
		}
		assertEquals(1, messageDigests);
		
		DetailedReport detailedReport = reports.getDetailedReport();
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		for (TimestampWrapper timestamp : timestampList) {
			assertEquals(TimestampType.CONTENT_TIMESTAMP, timestamp.getType());
			
			assertFalse(timestamp.isMessageImprintDataFound());
			assertFalse(timestamp.isMessageImprintDataIntact());
			assertTrue(timestamp.isSignatureIntact());
			assertTrue(timestamp.isSignatureValid());
			
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
