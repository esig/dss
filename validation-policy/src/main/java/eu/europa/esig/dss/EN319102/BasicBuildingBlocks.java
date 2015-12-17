package eu.europa.esig.dss.EN319102;

import eu.europa.esig.dss.EN319102.bbb.FormatChecking;
import eu.europa.esig.dss.EN319102.bbb.RevocationFreshnessChecker;
import eu.europa.esig.dss.EN319102.bbb.cv.CryptographicVerification;
import eu.europa.esig.dss.EN319102.bbb.isc.IdentificationOfTheSigningCertificate;
import eu.europa.esig.dss.EN319102.bbb.sav.SignatureAcceptanceValidation;
import eu.europa.esig.dss.EN319102.bbb.vci.ValidationContextInitialization;
import eu.europa.esig.dss.EN319102.bbb.xcv.X509CertificateValidation;

/**
 * 5.2 Basic building blocks
 */
public class BasicBuildingBlocks {

	private FormatChecking formatChecking;

	private IdentificationOfTheSigningCertificate isc;
	private ValidationContextInitialization vci;

	private RevocationFreshnessChecker rfc;

	private X509CertificateValidation xcv;
	private CryptographicVerification cv;
	private SignatureAcceptanceValidation sav;

	public void execute() {
		executeFormatChecking();
		executeIdentificationOfTheSigningCertificate();
		executeValidationContextInitialization();
		executeRevocationFreshnessChecker();
		executeX509CertificateValidation();
		executeCryptographicVerification();
		executeSignatureAcceptanceValidation();
	}

	void executeFormatChecking() {
		formatChecking.execute();
	}

	void executeIdentificationOfTheSigningCertificate() {
		isc.execute();
	}

	void executeValidationContextInitialization() {
		vci.execute();
	}

	private void executeRevocationFreshnessChecker() {
		rfc.execute();
	}

	void executeX509CertificateValidation() {
		xcv.execute();
	}

	void executeCryptographicVerification() {
		cv.execute();
	}

	void executeSignatureAcceptanceValidation() {
		sav.execute();
	}

}
