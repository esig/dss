package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class CAdESDetachedWithTstV2Test extends PKIFactoryAccess {
	
	private static DSSDocument detached;
	
	@BeforeAll
	public static void init() {
		detached = new InMemoryDocument("aaa".getBytes(), "data.txt");
	}
	
	@Test
	public void test() {
		
		DSSDocument document = new FileDocument("src/test/resources/validation/dss-2011/cades-tstv2-detached.p7s");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		validator.setDetachedContents(Collections.singletonList(detached));
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isSignatureIntact());
		assertTrue(signature.isSignatureValid());
		assertTrue(signature.isBLevelTechnicallyValid());
		
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertEquals(1, digestMatchers.size());
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			assertTrue(digestMatcher.isDataFound());
			assertTrue(digestMatcher.isDataIntact());
		}
		
		int v2ArchiveTsts = 0;
		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			if (ArchiveTimestampType.CAdES_V2.equals(timestamp.getArchiveTimestampType())) {
				assertTrue(timestamp.isMessageImprintDataFound());
				assertTrue(timestamp.isMessageImprintDataIntact());
				++v2ArchiveTsts;
			}
		}
		assertEquals(1, v2ArchiveTsts);
		
	}
	
	@Test
	public void noDetachedProvidedtest() {
		
		DSSDocument document = new FileDocument("src/test/resources/validation/dss-2011/cades-tstv2-detached.p7s");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signature.isSignatureIntact());
		assertFalse(signature.isSignatureValid());
		assertFalse(signature.isBLevelTechnicallyValid());
		
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertEquals(1, digestMatchers.size());
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			assertFalse(digestMatcher.isDataFound());
			assertFalse(digestMatcher.isDataIntact());
		}
		
		int v2ArchiveTsts = 0;
		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			if (ArchiveTimestampType.CAdES_V2.equals(timestamp.getArchiveTimestampType())) {
				assertFalse(timestamp.isMessageImprintDataFound());
				assertFalse(timestamp.isMessageImprintDataIntact());
				++v2ArchiveTsts;
			}
		}
		assertEquals(1, v2ArchiveTsts);
		
	}
	
	@Test
	public void digestDocumentProvidedtest() {
		
		DSSDocument document = new FileDocument("src/test/resources/validation/dss-2011/cades-tstv2-detached.p7s");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		DigestDocument digestDocument = new DigestDocument();
		digestDocument.addDigest(DigestAlgorithm.SHA256, detached.getDigest(DigestAlgorithm.SHA256));
		
		validator.setDetachedContents(Collections.singletonList(digestDocument));
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isSignatureIntact());
		assertTrue(signature.isSignatureValid());
		assertTrue(signature.isBLevelTechnicallyValid());
		
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertEquals(1, digestMatchers.size());
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			assertTrue(digestMatcher.isDataFound());
			assertTrue(digestMatcher.isDataIntact());
		}
		
		// not able to compute message imprint for ATSTv2 without original binaries
		int v2ArchiveTsts = 0;
		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			if (ArchiveTimestampType.CAdES_V2.equals(timestamp.getArchiveTimestampType())) {
				assertFalse(timestamp.isMessageImprintDataFound());
				assertFalse(timestamp.isMessageImprintDataIntact());
				++v2ArchiveTsts;
			}
		}
		assertEquals(1, v2ArchiveTsts);
		
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
