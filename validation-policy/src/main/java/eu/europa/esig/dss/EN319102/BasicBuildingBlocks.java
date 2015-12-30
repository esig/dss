package eu.europa.esig.dss.EN319102;

import java.util.Date;

import eu.europa.esig.dss.EN319102.bbb.cv.CryptographicVerification;
import eu.europa.esig.dss.EN319102.bbb.isc.IdentificationOfTheSigningCertificate;
import eu.europa.esig.dss.EN319102.bbb.sav.SignatureAcceptanceValidation;
import eu.europa.esig.dss.EN319102.bbb.vci.ValidationContextInitialization;
import eu.europa.esig.dss.EN319102.bbb.xcv.X509CertificateValidation;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlVCI;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.CertificateWrapper;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.report.DiagnosticData;

/**
 * 5.2 Basic building blocks
 */
public class BasicBuildingBlocks {

	private final DiagnosticData diagnosticData;
	private final SignatureWrapper signature;
	private final ValidationPolicy policy;
	private final Date currentTime;

	public BasicBuildingBlocks(DiagnosticData diagnosticData, SignatureWrapper signature, Date currentTime, ValidationPolicy policy) {
		this.diagnosticData = diagnosticData;
		this.signature = signature;
		this.currentTime = currentTime;
		this.policy = policy;
	}

	public XmlBasicBuildingBlocks execute() {
		XmlBasicBuildingBlocks result = new XmlBasicBuildingBlocks();

		/**
		 * 5.3.4 1) The Basic Signature validation process shall perform the format checking as per clause 5.2.2.
		 * 
		 * If the process returns PASSED, the Basic Signature validation process shall continue with the next
		 * step.
		 * 
		 * Otherwise the Basic Signature validation process shall return the indication INDETERMINATE with the
		 * sub-indication FORMAT_FAILURE.
		 */
		// TODO

		/**
		 * 5.3.4 2) The Basic Signature validation process shall perform the identification of the signing certificate
		 * (as per clause 5.2.3) with the signature and the signing certificate, if provided as a parameter.
		 * 
		 * If the identification of the signing certificate process returns the indication INDETERMINATE with the
		 * sub-indication NO_SIGNING_CERTIFICATE_FOUND, the Basic Signature validation process shall return the
		 * indication INDETERMINATE with the sub-indication NO_SIGNING_CERTIFICATE_FOUND,
		 * 
		 * otherwise it shall go to the next step.
		 */
		XmlISC isc = executeIdentificationOfTheSigningCertificate();
		result.setISC(isc);

		XmlConclusion iscConclusion = isc.getConclusion();
		if (Indication.INDETERMINATE.equals(iscConclusion.getIndication())
				&& SubIndication.NO_SIGNING_CERTIFICATE_FOUND.equals(iscConclusion.getSubIndication())) {
			result.setConclusion(iscConclusion);
			return result;
		}

		/**
		 * 5.3.4 3) The Basic Signature validation process shall perform the Validation Context Initialization as per
		 * clause 5.2.4.
		 * 
		 * If the process returns INDETERMINATE with some sub-indication, return with the indication INDETERMINATE
		 * together with that sub-indication,
		 * 
		 * otherwise go to the next step.
		 */
		XmlVCI vci = executeValidationContextInitialization();
		result.setVCI(vci);

		XmlConclusion vciConclusion = vci.getConclusion();
		if (Indication.INDETERMINATE.equals(vciConclusion.getIndication())) {
			result.setConclusion(vciConclusion);
			return result;
		}

		/**
		 * 5.3.4 4) The Basic Signature validation process shall perform the Cryptographic Verification process as per
		 * clause 5.2.7 with the following inputs:
		 * 
		 * a) The signature.
		 * b) The certificate chain returned in the previous step. And
		 * c) The signed data object(s).
		 * 
		 * If the cryptographic signature validation process returns PASSED, the Basic Signature validation process
		 * shall go to the next step.
		 * 
		 * Otherwise, the Basic Signature validation process shall return the returned indication, subindication and
		 * associated information provided by the cryptographic signature validation process.
		 */
		XmlCV cv = executeCryptographicVerification();
		result.setCV(cv);

		XmlConclusion cvConclusion = cv.getConclusion();
		if (!Indication.VALID.equals(cvConclusion.getIndication())) {
			result.setConclusion(cvConclusion);
			return result;
		}

		/**
		 * 5.3.4 5) The Basic Signature validation process shall perform the X.509 Certificate Validation as per clause
		 * 5.2.6 with the following inputs:
		 * 
		 * a) The signing certificate obtained in step 1. And
		 * b) X.509 validation constraints, certificate validation-data, chain constraints and cryptographic constraints
		 * obtained in step 3 or provided as input.
		 * 
		 * If the signing certificate validation process returns the indication PASSED, the Basic Signature validation
		 * process shall go to the next step.
		 * 
		 * If the signing certificate validation process returns the indication INDETERMINATE with the sub-indication
		 * REVOKED_NO_POE and if the signature contains a content-time-stamp attribute, the Basic Signature validation
		 * process shall perform the validation process for AdES time-stamps as defined in clause 5.4. If this process
		 * returns the indication PASSED and the generation time of the time-stamp token is after the revocation time,
		 * the Basic Signature validation process shall return the indication FAILED with the sub-indication REVOKED. In
		 * all other cases, the Basic Signature validation process shall return the indication INDETERMINATE with the
		 * sub-indication REVOKED_NO_POE.
		 * 
		 * If the signing certificate validation process returns the indication INDETERMINATE with the sub-indication
		 * OUT_OF_BOUNDS_NO_POE and if the signature contains a content-time-stamp attribute, the Basic Signature
		 * validation process shall perform the validation process for AdES time-stamps as defined in clause 5.4. If it
		 * returns the indication PASSED and the generation time of the time-stamp token is after the expiration date of
		 * the signing certificate, the Basic Signature validation process shall return the indication INDETERMINATE
		 * with the sub-indication EXPIRED. Otherwise, the Basic Signature validation process shall return the
		 * indication INDETERMINATE with the sub-indication OUT_OF_BOUNDS_NO_POE.
		 * 
		 * In all other cases, the Basic Signature validation process shall return the indication, sub-indication and
		 * any associated information returned by the signing certificate validation process.
		 */
		XmlXCV xcv = executeX509CertificateValidation();
		result.setXCV(xcv);

		XmlConclusion xcvConclusion = xcv.getConclusion();
		// TODO not correct !!
		if (!Indication.VALID.equals(xcvConclusion.getIndication())) {
			result.setConclusion(xcvConclusion);
			return result;
		}

		/**
		 * 5.3.4 6) The Basic Signature validation process shall perform the Signature Acceptance Validation process as
		 * per clause 5.2.8 with the following inputs:
		 * a) The signature.
		 * b) The Cryptographic Constraints. And
		 * c) The Signature Elements Constraints.
		 * 
		 * If the signature acceptance validation process returns PASSED, the Basic Signature validation process shall
		 * go to the next step.
		 * 
		 * If the signature acceptance validation process returns the indication INDETERMINATE with the sub-indication
		 * CRYPTO_CONSTRAINTS_FAILURE_NO_POE and the material concerned by this failure is the signature value and if
		 * the signature contains a content-time-stamp attribute, the Basic Signature validation process shall perform
		 * the validation process for AdES time-stamps as defined in clause 5.4. If it returns the indication PASSED and
		 * the algorithm(s) concerned were no longer considered reliable at the generation time of the timestamp token,
		 * the Basic Signature validation process shall return the indication FAILED with the sub-indication
		 * CRYPTO_CONSTRAINTS_FAILURE. In all other cases, the Basic Signature validation process shall return the
		 * indication INDETERMINATE with the sub-indication CRYPTO_CONSTRAINTS_FAILURE_NO_POE.
		 * 
		 * NOTE 2: The content time-stamp is a signed attribute and hence proves that the signature value was produced
		 * after the generation time of the time-stamp token.
		 * NOTE 3: In case this clause returns INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE, the validation process
		 * for signature with long-term validation data and with archival data can be used to validate the signature, if
		 * other POE (e.g. from a trusted archive) exist.
		 *
		 * In all other cases, the Basic Signature validation process shall return the indication and associated
		 * information returned by the signature acceptance validation building block.
		 */

		XmlSAV sav = executeSignatureAcceptanceValidation();
		result.setSAV(sav);

		XmlConclusion savConclusion = sav.getConclusion();
		if (Indication.INDETERMINATE.equals(savConclusion.getIndication())
				&& SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(savConclusion.getSubIndication())) {
			// TODO
		}

		/**
		 * 5.3.4 7) The Basic Signature validation process shall return the success indication PASSED.
		 * In addition, the Basic Signature validation process should return additional information extracted from the
		 * signature and/or used by the intermediate steps.
		 * In particular, the SVA should provide to the DA all information related to signed and unsigned attributes,
		 * including those which were not processed during the validation process.
		 */

		XmlConclusion conclusion = new XmlConclusion();
		conclusion.setIndication(Indication.VALID);
		result.setConclusion(conclusion);

		return result;
	}

	private XmlISC executeIdentificationOfTheSigningCertificate() {
		IdentificationOfTheSigningCertificate isc = new IdentificationOfTheSigningCertificate(diagnosticData, signature, policy);
		return isc.execute();
	}

	private XmlVCI executeValidationContextInitialization() {
		ValidationContextInitialization vci = new ValidationContextInitialization(signature, policy);
		return vci.execute();
	}

	private XmlCV executeCryptographicVerification() {
		CryptographicVerification cv = new CryptographicVerification(signature, policy);
		return cv.execute();
	}

	private XmlXCV executeX509CertificateValidation() {
		// Not null because of ISC
		CertificateWrapper certificate = diagnosticData.getUsedCertificateByIdNullSafe(signature.getSigningCertificateId());
		X509CertificateValidation xcv = new X509CertificateValidation(diagnosticData, certificate, currentTime, Context.MAIN_SIGNATURE, policy);
		return xcv.execute();
	}

	private XmlSAV executeSignatureAcceptanceValidation() {
		SignatureAcceptanceValidation sav = new SignatureAcceptanceValidation(diagnosticData, currentTime, signature, policy);
		return sav.execute();
	}

	void executeFormatChecking() {
		// formatChecking.execute();
	}

	void executeRevocationFreshnessChecker() {
		// rfc.execute();
	}

}
