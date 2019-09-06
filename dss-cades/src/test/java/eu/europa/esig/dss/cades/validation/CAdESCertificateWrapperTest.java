package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class CAdESCertificateWrapperTest extends PKIFactoryAccess {
	
	@Test
	public void certificateSourcesTest() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/cades/CAdES-Baseline_profile_LT/Sample_Set_3/Signature-CBp-LT-2.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<CertificateWrapper> certificates = diagnosticData.getUsedCertificates();
		int certsFromOcspResponse = 0;
		int certsFromTimestamp = 0;
		int certsFromMoreThanTwoSources = 0;
		for (CertificateWrapper certificate : certificates) {
			assertNotNull(certificate.getSources());
			assertNotEquals(0, certificate.getSources().size());
			if (certificate.getSources().contains(CertificateSourceType.OCSP_RESPONSE)) {
				assertTrue(certificate.getSources().size() > 1);
				certsFromOcspResponse++;
			}
			if (certificate.getSources().contains(CertificateSourceType.TIMESTAMP)) {
				assertTrue(certificate.getSources().size() > 1);
				certsFromTimestamp++;
			}
			if (certificate.getSources().size() > 2) {
				certsFromMoreThanTwoSources++;
				assertEquals(3, certificate.getSources().size());
			}
			assertFalse(certificate.getSources().contains(CertificateSourceType.UNKNOWN));
		}
		assertEquals(3, certsFromOcspResponse);
		assertEquals(2, certsFromTimestamp);
		assertEquals(1, certsFromMoreThanTwoSources);
		
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlRelatedCertificate> foundCertificates = signatureWrapper.getRelatedCertificates();
		assertNotNull(foundCertificates);
		assertEquals(5, foundCertificates.size());
		List<XmlFoundCertificate> signinigCertificates = signatureWrapper.getFoundCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
		assertNotNull(foundCertificates);
		assertEquals(1, signinigCertificates.size());
		XmlFoundCertificate signCertificate = signinigCertificates.get(0);
		List<XmlCertificateRef> certificateRefs = signCertificate.getCertificateRefs();
		assertNotNull(certificateRefs);
		XmlCertificateRef certRef = certificateRefs.get(0);
		assertNotNull(certRef.getDigestAlgoAndValue());
		assertNotNull(certRef.getDigestAlgoAndValue().getDigestMethod());
		assertNotNull(certRef.getDigestAlgoAndValue().getDigestValue());
		assertNotNull(certRef.getIssuerSerial());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
