package eu.europa.esig.dss.xades.validation.dkcert;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.text.ParseException;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class DKOtherCertTest extends AbstractDKTestCertificate {
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		try {
			SignedDocumentValidator validator = super.getValidator(signedDocument);
			CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
			CommonTrustedCertificateSource certSource = new CommonTrustedCertificateSource();
			certSource.addCertificate(WRONG);
			certificateVerifier.setTrustedCertSource(certSource);
			certificateVerifier.setDataLoader(getMemoryDataLoader());
			validator.setCertificateVerifier(certificateVerifier);
			validator.setProcessExecutor(fixedTime());
			return validator;
		} catch (ParseException e) {
			fail(e);
			return null;
		}
	}
	
	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}

}
