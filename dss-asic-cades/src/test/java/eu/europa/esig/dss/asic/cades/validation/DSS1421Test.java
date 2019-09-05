package eu.europa.esig.dss.asic.cades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1421Test extends PKIFactoryAccess {
	
	@Test
	public void test() {
		DSSDocument document = new FileDocument("src/test/resources/validation/dss1421.asice");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
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
			}
		}
		assertEquals(1, archiveTimestampCounter);
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
