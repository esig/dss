package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class XAdESLTAKeyInfoCertTest extends PKIFactoryAccess {
	
	@Test
	public void test() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/xades-lta-with-additional-cert-in-keyinfo.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		// reports.print();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		List<RelatedCertificateWrapper> keyInfoCerts = signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.KEY_INFO);
		assertEquals(3, keyInfoCerts.size());
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		boolean archiveTstFound = false;
		for (TimestampWrapper timestampWrapper : timestampList) {
			if (timestampWrapper.getType().isArchivalTimestamp()) {
				List<String> certIds = timestampWrapper.getTimestampedCertificates().stream().map(CertificateWrapper::getId).collect(Collectors.toList());
				for (CertificateWrapper certificateWrapper : keyInfoCerts) {
					assertTrue(certIds.contains(certificateWrapper.getId()));
				}
				archiveTstFound = true;
			} else {
				assertTrue(timestampWrapper.getType().isSignatureTimestamp());
				assertEquals(1, timestampWrapper.getTimestampedCertificates().size());
			}
		}
		assertTrue(archiveTstFound);
	}

	@Override
	protected String getSigningAlias() {
		// TODO Auto-generated method stub
		return null;
	}

}
