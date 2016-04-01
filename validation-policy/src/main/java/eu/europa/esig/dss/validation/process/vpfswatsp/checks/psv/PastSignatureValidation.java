package eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlPCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlPSV;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.pcv.PastCertificateValidation;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.BestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpirationCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.BestSignatureTimeNotBeforeCertificateIssuanceCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.POEExistsCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.PastCertificateValidationAcceptableCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.PastCertificateValidationCheck;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.TokenProxy;

public class PastSignatureValidation extends Chain<XmlPSV> {

	private final TokenProxy token;
	private final DiagnosticData diagnosticData;
	private final XmlBasicBuildingBlocks bbb;
	private final POEExtraction poe;
	private final Date currentTime;

	private final ValidationPolicy policy;
	private final Context context;

	public PastSignatureValidation(TokenProxy token, DiagnosticData diagnosticData, XmlBasicBuildingBlocks bbb, POEExtraction poe, Date currentTime,
			ValidationPolicy policy, Context context) {
		super(new XmlPSV());

		this.token = token;
		this.diagnosticData = diagnosticData;
		this.bbb = bbb;
		this.poe = poe;
		this.currentTime = currentTime;
		this.policy = policy;
		this.context = context;
	}

	@Override
	protected void initChain() {

		PastCertificateValidation pcv = new PastCertificateValidation(token, diagnosticData, bbb, poe, currentTime, policy, context);
		XmlPCV pcvResult = pcv.execute();
		bbb.setPCV(pcvResult);

		/*
		 * 1) The building block shall perform the past certificate validation process with the following inputs: the
		 * signature, the target certificate, the X.509 validation parameters, certificate validation data, chain
		 * constraints, cryptographic constraints and the set of POEs. If it returns PASSED/validation time, the
		 * building block shall go to the next step. Otherwise, the building block shall return the current time status
		 * and sub-indication with an explanation of the failure.
		 */
		ChainItem<XmlPSV> item = firstItem = pastCertificateValidationAcceptableCheck(pcvResult);

		Date controlTime = pcvResult.getControlTime();
		Indication currentTimeIndication = bbb.getConclusion().getIndication();
		SubIndication currentTimeSubIndication = bbb.getConclusion().getSubIndication();

		/*
		 * 2) If there is a POE of the signature value at (or before) the validation time returned in the previous step:
		 */
		if (controlTime != null && poe.isPOEExists(token.getId(), controlTime)) {

			/*
			 * If current time indication/sub-indication is INDETERMINATE/REVOKED_NO_POE or INDETERMINATE/
			 * REVOKED_CA_NO_POE, the building block shall return PASSED.
			 */
			if (Indication.INDETERMINATE.equals(currentTimeIndication)
					&& (SubIndication.REVOKED_NO_POE.equals(currentTimeSubIndication) || SubIndication.REVOKED_CA_NO_POE.equals(currentTimeSubIndication))) {
				item = item.setNextItem(poeExist());
				return;
			}

			/*
			 * If current time indication/sub-indication is INDETERMINATE/OUT_OF_BOUNDS_NO_POE:
			 * 
			 * a) If best-signature-time (lowest time at which there exists a POE for the signature value in the set of
			 * POEs) is before the issuance date of the signing certificate (notBefore field), the building block
			 * shall return the indication INDETERMINATE with the sub-indication NOT_YET_VALID.
			 * 
			 * b) If best-signature-time (lowest time at which there exists a POE for the signature value in the set of
			 * POEs) is after the issuance date and before the expiration date of the signing certificate, the
			 * building block shall return the status indication PASSED.
			 */

			else if (Indication.INDETERMINATE.equals(currentTimeIndication) && SubIndication.OUT_OF_BOUNDS_NO_POE.equals(currentTimeSubIndication)) {

				Date bestSignatureTime = poe.getLowestPOE(token.getId(), controlTime);
				CertificateWrapper signingCertificate = diagnosticData.getUsedCertificateById(token.getSigningCertificateId());

				item = item.setNextItem(bestSignatureTimeNotBeforeCertificateIssuance(bestSignatureTime, signingCertificate));
				item = item.setNextItem(bestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpiration(bestSignatureTime, signingCertificate));
				return;
			}

			/*
			 * 3) If current time indication/ sub-indication is INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE and for
			 * each algorithm (or key size) in the list concerned by the failure, there is a POE for the material that
			 * uses this algorithm (or key size) at a time before the time up to which the algorithm in question was
			 * considered secure, the building block shall return the status indication PASSED.
			 */

			else if (Indication.INDETERMINATE.equals(currentTimeIndication)
					&& SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(currentTimeSubIndication)) {
				// TODO
			}

		}

		/*
		 * 4) In all other cases, the building block shall return the current time indication/ sub-indication together
		 * with an explanation of the failure.
		 */
		else {
			item = item.setNextItem(pastCertificateValidationCheck(pcvResult));
		}

	}

	private ChainItem<XmlPSV> pastCertificateValidationAcceptableCheck(XmlPCV pcvResult) {
		return new PastCertificateValidationAcceptableCheck(result, pcvResult, getFailLevelConstraint());
	}

	private ChainItem<XmlPSV> pastCertificateValidationCheck(XmlPCV pcvResult) {
		return new PastCertificateValidationCheck(result, pcvResult, getFailLevelConstraint());
	}

	private ChainItem<XmlPSV> poeExist() {
		return new POEExistsCheck(result, getFailLevelConstraint());
	}

	private ChainItem<XmlPSV> bestSignatureTimeNotBeforeCertificateIssuance(Date bestSignatureTime, CertificateWrapper signingCertificate) {
		return new BestSignatureTimeNotBeforeCertificateIssuanceCheck(result, bestSignatureTime, signingCertificate, getFailLevelConstraint());
	}

	private ChainItem<XmlPSV> bestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpiration(Date bestSignatureTime,
			CertificateWrapper signingCertificate) {
		return new BestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpirationCheck(result, bestSignatureTime, signingCertificate,
				getFailLevelConstraint());
	}

}
