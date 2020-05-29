package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class XAdESRefreshedOCSPCertificateTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/xades-with-equivalent-certs.xml");
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
		validator.setCertificateVerifier(certificateVerifier);
		return validator;
	}
	
	@Override
	protected void checkCertificates(DiagnosticData diagnosticData) {
		super.checkCertificates(diagnosticData);
		
		boolean equivalentCertsFound = false;
		for (CertificateWrapper certificateWrapper : diagnosticData.getUsedCertificates()) {
			List<CertificateWrapper> equivalentCertificates = diagnosticData.getEquivalentCertificates(certificateWrapper);
			if (Utils.isCollectionNotEmpty(equivalentCertificates)) {
				equivalentCertsFound = true;
				for (CertificateWrapper equivalentCert : equivalentCertificates) {
					assertEquals(certificateWrapper.getEntityKey(), equivalentCert.getEntityKey());
					assertEquals(certificateWrapper.getCertificateDN(), equivalentCert.getCertificateDN());
					assertEquals(certificateWrapper.getCertificateIssuerDN(), equivalentCert.getCertificateIssuerDN());
					assertNotEquals(certificateWrapper.getNotBefore(), equivalentCert.getNotBefore());
					assertNotEquals(certificateWrapper.getNotAfter(), equivalentCert.getNotAfter());
					assertNotEquals(certificateWrapper.getDigestAlgorithm(), equivalentCert.getDigestAlgorithm());
				}
			}
		}
		assertTrue(equivalentCertsFound);
	}

}
