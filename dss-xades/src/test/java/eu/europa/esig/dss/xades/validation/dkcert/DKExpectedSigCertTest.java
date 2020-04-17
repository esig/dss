package eu.europa.esig.dss.xades.validation.dkcert;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.text.ParseException;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class DKExpectedSigCertTest extends AbstractDKTestCertificate {
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		try {
			SignedDocumentValidator validator = super.getValidator(signedDocument);
			CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
			CommonTrustedCertificateSource certSource = new CommonTrustedCertificateSource();
			certSource.addCertificate(EXPECTED_SIG_CERT);
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
	protected void checkTokens(DiagnosticData diagnosticData) {
		super.checkTokens(diagnosticData);
		for (CertificateWrapper certificateWrapper : diagnosticData.getUsedCertificates()) {
			assertFalse(certificateWrapper.isTrusted());
		}
	}
	
	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void certs() {
		// System.out.println(PREVIOUS_SIG_CERT);
		// System.out.println(EXPECTED_SIG_CERT);

		assertFalse(PREVIOUS_SIG_CERT.isEquivalent(EXPECTED_SIG_CERT));
		assertFalse(PREVIOUS_SIG_CERT.isEquivalent(AIA_CERT));
		assertFalse(EXPECTED_SIG_CERT.isEquivalent(AIA_CERT));
		assertFalse(PREVIOUS_SIG_CERT.getPublicKey().equals(EXPECTED_SIG_CERT.getPublicKey()));
		assertFalse(PREVIOUS_SIG_CERT.getPublicKey().equals(AIA_CERT.getPublicKey()));
		assertFalse(EXPECTED_SIG_CERT.getPublicKey().equals(AIA_CERT.getPublicKey()));
		assertFalse(PREVIOUS_SIG_CERT.getEntityKey().equals(EXPECTED_SIG_CERT.getEntityKey()));
		assertFalse(PREVIOUS_SIG_CERT.getEntityKey().equals(AIA_CERT.getEntityKey()));
		assertFalse(EXPECTED_SIG_CERT.getEntityKey().equals(AIA_CERT.getEntityKey()));
		assertFalse(PREVIOUS_SIG_CERT.getDSSId().equals(EXPECTED_SIG_CERT.getDSSId()));
		assertFalse(PREVIOUS_SIG_CERT.getDSSId().equals(AIA_CERT.getDSSId()));
		assertFalse(EXPECTED_SIG_CERT.getDSSId().equals(AIA_CERT.getDSSId()));
		assertTrue(PREVIOUS_SIG_CERT.getSubject().equals(EXPECTED_SIG_CERT.getSubject()));
	}

}
