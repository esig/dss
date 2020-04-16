package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class CAdESNoKeInfoTrustedStoreTest extends AbstractCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/no-key-info-cert.pkcs7");
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		CertificateToken signingCertificateToken = DSSUtils.loadCertificate(new File("src/test/resources/validation/signCert.cer"));
		
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		CommonTrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
		trustedCertSource.addCertificate(signingCertificateToken);
		commonCertificateVerifier.setTrustedCertSource(trustedCertSource);
		validator.setCertificateVerifier(commonCertificateVerifier);
		
		// the signing certificates are checked only from the embedded certs
		validator.defineSigningCertificate(signingCertificateToken);
		
		return validator;
	}
	
	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);
		
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

}
