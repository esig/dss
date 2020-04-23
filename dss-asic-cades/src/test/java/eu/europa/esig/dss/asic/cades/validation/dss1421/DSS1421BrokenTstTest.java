package eu.europa.esig.dss.asic.cades.validation.dss1421;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.asic.cades.validation.AbstractASiCWithCAdESTestValidation;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;

public class DSS1421BrokenTstTest extends AbstractASiCWithCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss1421-broken.asice");
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		List<CertificateWrapper> certificatesFromTimestamps = diagnosticData.getCertificatesFromSource(CertificateSourceType.TIMESTAMP);
		assertEquals(5, certificatesFromTimestamps.size());
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<TimestampWrapper> timestamps = signature.getTimestampList();
		assertEquals(2, timestamps.size());
		int archiveTimestampCounter = 0;
		for (TimestampWrapper timestamp : timestamps) {
			CertificateWrapper timestampSigningCertificate = timestamp.getSigningCertificate();
			assertNotNull(timestampSigningCertificate);
			assertTrue(Utils.isCollectionNotEmpty(timestamp.getCertificateChain()));
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
				assertTrue(certificatesFromTimestamps.contains(timestampSigningCertificate));
				assertEquals(ArchiveTimestampType.CAdES_DETACHED, timestamp.getArchiveTimestampType());
				archiveTimestampCounter++;
				
				List<XmlDigestMatcher> digestMatchers = timestamp.getDigestMatchers();
				boolean validMessageImprint = true;
				for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
					if (DigestMatcherType.MESSAGE_IMPRINT == xmlDigestMatcher.getType()) {
						validMessageImprint = xmlDigestMatcher.isDataIntact();
					}
				}
				assertFalse(validMessageImprint);
				assertTrue(timestamp.isMessageImprintDataFound());
				assertFalse(timestamp.isMessageImprintDataIntact());
			}
			assertTrue(timestamp.isSignatureValid());
		}
		assertEquals(1, archiveTimestampCounter);
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertFalse(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

}