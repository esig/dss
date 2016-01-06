package eu.europa.esig.dss.EN319102;

import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.commons.collections.CollectionUtils;

import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlVCI;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessBasicSignatures;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.CertificateWrapper;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.TimestampWrapper;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.dss.x509.TimestampType;

/**
 * 5.3 Validation process for Basic Signatures
 */
public class ValidationProcessForBasicSignatures {

	private final DiagnosticData diagnosticData;

	private final XmlBasicBuildingBlocks signatureBBB;
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	public ValidationProcessForBasicSignatures(DiagnosticData diagnosticData, XmlBasicBuildingBlocks signatureBBB, Map<String, XmlBasicBuildingBlocks> bbbs) {
		this.diagnosticData = diagnosticData;
		this.signatureBBB = signatureBBB;
		this.bbbs = bbbs;
	}

	public XmlValidationProcessBasicSignatures execute() {
		XmlValidationProcessBasicSignatures result = new XmlValidationProcessBasicSignatures();

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
		XmlISC isc = signatureBBB.getISC();
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
		XmlVCI vci = signatureBBB.getVCI();
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
		 * Otherwise, the Basic Signature validation process shall return the returned indication, sub-indication and
		 * associated information provided by the cryptographic signature validation process.
		 */
		XmlCV cv = signatureBBB.getCV();
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
		XmlXCV xcv = signatureBBB.getXCV();
		XmlConclusion xcvConclusion = xcv.getConclusion();
		if (Indication.INDETERMINATE.equals(xcvConclusion.getIndication()) && SubIndication.REVOKED_NO_POE.equals(xcvConclusion.getSubIndication())) {
			SignatureWrapper currentSignature = diagnosticData.getSignatureById(signatureBBB.getId());
			List<TimestampWrapper> contentTimestamps = currentSignature.getTimestampListByType(TimestampType.CONTENT_TIMESTAMP);
			if (CollectionUtils.isNotEmpty(contentTimestamps)) {
				boolean failed = false;
				Date revocationDate = getRevocationDateForSigningCertificate(currentSignature);
				for (TimestampWrapper timestamp : contentTimestamps) {
					if (isValidTimestamp(timestamp)) {
						Date tspProductionTime = timestamp.getProductionTime();
						if (tspProductionTime.after(revocationDate)) {
							failed = true;
							break;
						}
					}
				}

				if (failed) {
					XmlConclusion conclusion = new XmlConclusion();
					conclusion.setIndication(Indication.INVALID);
					conclusion.setSubIndication(SubIndication.REVOKED);
					result.setConclusion(conclusion);
					return result;
				}
			}
		} else if (Indication.INDETERMINATE.equals(xcvConclusion.getIndication())
				&& SubIndication.OUT_OF_BOUNDS_NO_POE.equals(xcvConclusion.getSubIndication())) {
			SignatureWrapper currentSignature = diagnosticData.getSignatureById(signatureBBB.getId());
			List<TimestampWrapper> contentTimestamps = currentSignature.getTimestampListByType(TimestampType.CONTENT_TIMESTAMP);
			if (CollectionUtils.isNotEmpty(contentTimestamps)) {
				boolean failed = false;
				Date expirationDate = getExpirationDateForSigningCertificate(currentSignature);
				for (TimestampWrapper timestamp : contentTimestamps) {
					if (isValidTimestamp(timestamp)) {
						Date tspProductionTime = timestamp.getProductionTime();
						if (tspProductionTime.after(expirationDate)) {
							failed = true;
							break;
						}
					}
				}

				if (failed) {
					XmlConclusion conclusion = new XmlConclusion();
					conclusion.setIndication(Indication.INDETERMINATE);
					conclusion.setSubIndication(SubIndication.EXPIRED);
					result.setConclusion(conclusion);
					return result;
				}
			}
		} else if (!Indication.VALID.equals(xcvConclusion.getIndication())) {
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
		XmlSAV sav = signatureBBB.getSAV();
		XmlConclusion savConclusion = sav.getConclusion();
		if (Indication.INDETERMINATE.equals(savConclusion.getIndication())
				&& SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(savConclusion.getSubIndication())) {

			SignatureWrapper currentSignature = diagnosticData.getSignatureById(signatureBBB.getId());
			List<TimestampWrapper> contentTimestamps = currentSignature.getTimestampListByType(TimestampType.CONTENT_TIMESTAMP);
			if (CollectionUtils.isNotEmpty(contentTimestamps)) {
				boolean failed = false;
				for (TimestampWrapper timestamp : contentTimestamps) {
					if (isValidTimestamp(timestamp)) {
						failed = true;
						break;
					}
				}

				if (failed) {
					XmlConclusion conclusion = new XmlConclusion();
					conclusion.setIndication(Indication.INVALID);
					conclusion.setSubIndication(SubIndication.CRYPTO_CONSTRAINTS_FAILURE);
					result.setConclusion(conclusion);
					return result;
				}
			}

		} else if (!Indication.VALID.equals(savConclusion.getIndication())) {
			result.setConclusion(savConclusion);
			return result;
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

	private boolean isValidTimestamp(TimestampWrapper timestamp) {
		XmlBasicBuildingBlocks timestampBasicBuildingBlocks = bbbs.get(timestamp.getId());
		return (timestampBasicBuildingBlocks != null && timestampBasicBuildingBlocks.getConclusion() != null)
				&& Indication.VALID.equals(timestampBasicBuildingBlocks.getConclusion().getIndication());
	}

	private Date getRevocationDateForSigningCertificate(SignatureWrapper currentSignature) {
		CertificateWrapper signingCertificate = diagnosticData.getUsedCertificateById(currentSignature.getSigningCertificateId());
		if (signingCertificate != null && signingCertificate.getRevocationData() != null) {
			return signingCertificate.getRevocationData().getDateTime();
		}
		return null;
	}

	private Date getExpirationDateForSigningCertificate(SignatureWrapper currentSignature) {
		CertificateWrapper signingCertificate = diagnosticData.getUsedCertificateById(currentSignature.getSigningCertificateId());
		if (signingCertificate != null) {
			return signingCertificate.getNotAfter();
		}
		return null;
	}

}
