package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CertificateOriginType;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.RevocationType;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.XmlRevocationOrigin;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.x509.TimestampType;

public class DSS1647Test {

	@Test
	public void test() {
		DSSDocument doc = new FileDocument("C:\\Users\\aleksandr.beliakov\\Downloads\\OJ_L_2018_109_FULL.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		//commonCertificateVerifier.setIncludeCertificateRevocationValues(true);
		validator.setCertificateVerifier(commonCertificateVerifier);
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<TimestampWrapper> timestamps = diagnosticData.getTimestampList();
		assertEquals(2, timestamps.size());
		
		TimestampWrapper archiveTimestamp = timestamps.get(1);
		assertEquals(TimestampType.ARCHIVE_TIMESTAMP, archiveTimestamp.getType());
		assertEquals(4, archiveTimestamp.getTimestampedCertificateIds().size());
		assertEquals(3, archiveTimestamp.getTimestampedRevocationIds().size());
		assertEquals(1, archiveTimestamp.getTimestampedTimestampIds().size());
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		List<String> timestampValidationDataCertificateIds = signature.getFoundCertificateIds(CertificateOriginType.TIMESTAMP_DATA_VALIDATION);
		assertEquals(1, timestampValidationDataCertificateIds.size());
		assertTrue(archiveTimestamp.getTimestampedCertificateIds().contains(timestampValidationDataCertificateIds.get(0)));
		
		List<String> certificateValueIds = signature.getFoundCertificateIds(CertificateOriginType.CERTIFICATE_VALUES);
		assertEquals(3, certificateValueIds.size());
		for (String certId : certificateValueIds) {
			assertTrue(archiveTimestamp.getTimestampedCertificateIds().contains(certId));
		}
		
		List<String> timestampValidationDataRevocationIds = signature.getRevocationIdsByOrigin(XmlRevocationOrigin.INTERNAL_TIMESTAMP_REVOCATION_VALUES);
		assertEquals(1, timestampValidationDataRevocationIds.size());
		assertTrue(archiveTimestamp.getTimestampedRevocationIds().contains(timestampValidationDataRevocationIds.get(0)));
		
		List<String> crlRevocationValueIds = signature.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, XmlRevocationOrigin.INTERNAL_REVOCATION_VALUES);
		assertEquals(1, crlRevocationValueIds.size());
		assertTrue(archiveTimestamp.getTimestampedRevocationIds().contains(crlRevocationValueIds.get(0)));
		
		List<String> ocspRevocationValueIds = signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_REVOCATION_VALUES);
		assertEquals(1, ocspRevocationValueIds.size());
		assertTrue(archiveTimestamp.getTimestampedRevocationIds().contains(ocspRevocationValueIds.get(0)));
	}

}
