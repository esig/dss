package eu.europa.esig.dss.validation.process.vpfltvd;

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSignature;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessTimestamps;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.AcceptableBasicSignatureValidationCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.BestSignatureTimeNotBeforeCertificateIssuanceCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.RevocationBasicBuildingBlocksCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.RevocationDateAfterBestSignatureTimeCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.SigningTimeAttributePresentCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.TimestampCoherenceOrderCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.TimestampDelayCheck;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;

/**
 * 5.5 Validation process for Signatures with Time and Signatures with Long-Term Validation Data
 */
public class ValidationProcessForSignaturesWithLongTermValidationData extends Chain<XmlValidationProcessLongTermData> {

	private static final Logger logger = LoggerFactory.getLogger(ValidationProcessForSignaturesWithLongTermValidationData.class);

	private final XmlConstraintsConclusion basicSignatureValidation;
	private final List<XmlValidationProcessTimestamps> timestampValidations;

	private final DiagnosticData diagnosticData;
	private final SignatureWrapper currentSignature;
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	private final ValidationPolicy policy;
	private final Date currentDate;

	public ValidationProcessForSignaturesWithLongTermValidationData(XmlSignature signatureAnalysis, DiagnosticData diagnosticData,
			SignatureWrapper currentSignature, Map<String, XmlBasicBuildingBlocks> bbbs, ValidationPolicy policy, Date currentDate) {
		super(new XmlValidationProcessLongTermData());

		this.basicSignatureValidation = signatureAnalysis.getValidationProcessBasicSignatures();
		this.timestampValidations = signatureAnalysis.getValidationProcessTimestamps();

		this.diagnosticData = diagnosticData;
		this.currentSignature = currentSignature;
		this.bbbs = bbbs;

		this.policy = policy;
		this.currentDate = currentDate;
	}

	@Override
	protected void initChain() {

		/*
		 * 1) The process shall initialize the set of signature time-stamp tokens from the signature time-stamp
		 * attributes present in the signature and shall initialize the best-signature-time to the current time.
		 * NOTE 1: Best-signature-time is an internal variable for the algorithm denoting the earliest time when it can
		 * be proven that a signature has existed.
		 */
		Date bestSignatureTime = currentDate;

		/*
		 * 5.5.4 2) Signature validation: the process shall perform the validation process for Basic Signatures as per
		 * clause 5.3 with all the inputs, including the processing of any signed attributes as specified. If the
		 * Signature contains long-term validation data, this data shall be passed to the validation process for Basic
		 * Signatures.
		 * 
		 * If this validation returns PASSED, INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE,
		 * INDETERMINATE/REVOKED_NO_POE or INDETERMINATE/OUT_OF_BOUNDS_NO_POE, the SVA
		 * shall go to the next step. Otherwise, the process shall return the status and information returned by the
		 * validation process for Basic Signatures.
		 */
		ChainItem<XmlValidationProcessLongTermData> item = firstItem = isAcceptableBasicSignatureValidation();

		Set<RevocationWrapper> revocationData = getLinkedRevocationData();
		if (Utils.isCollectionNotEmpty(revocationData)) {
			for (RevocationWrapper revocation : revocationData) {
				XmlBasicBuildingBlocks revocationBBB = bbbs.get(revocation.getId());
				if (revocationBBB != null) {
					item = item.setNextItem(revocationBasicBuildingBlocksValid(revocationBBB));
				} else {
					logger.warn("No BBB found for revocation " + revocation.getId());
				}
			}
		}

		/*
		 * 3) Signature time-stamp validation:
		 * a) For each time-stamp token in the set of signature time-stamp tokens, the process shall check that the
		 * message imprint has been generated according to the corresponding signature format specification
		 * verification. If the verification fails, the process shall remove the token from the set.
		 */
		Set<TimestampWrapper> allowedTimestamps = filterInvalidTimestamps(currentSignature.getTimestampList());

		if (Utils.isCollectionNotEmpty(allowedTimestamps)) {

			/*
			 * b) Time-stamp token validation: For each time-stamp token remaining in the set of signature time-stamp
			 * tokens, the process shall perform the time-stamp validation process as per clause 5.4:
			 * 
			 * If PASSED is returned and if the returned generation time is before best-signature-time, the process
			 * shall set best-signature-time to this date and shall try the next token.
			 */
			for (TimestampWrapper timestampWrapper : allowedTimestamps) {
				Date productionTime = timestampWrapper.getProductionTime();
				if (productionTime.before(bestSignatureTime)) {
					bestSignatureTime = productionTime;
				}
			}
		}

		/*
		 * 4) Comparing times:
		 * a) If step 2 returned the indication INDETERMINATE with the sub-indication REVOKED_NO_POE: If the
		 * returned revocation time is posterior to best-signature-time, the process shall perform step 4d.
		 * Otherwise, the process shall return the indication INDETERMINATE with the sub-indication REVOKED_NO_POE.
		 */
		XmlConclusion bsConclusion = basicSignatureValidation.getConclusion();
		if (Indication.INDETERMINATE.equals(bsConclusion.getIndication()) && SubIndication.REVOKED_NO_POE.equals(bsConclusion.getSubIndication())) {
			item = item.setNextItem(revocationDateAfterBestSignatureDate(bestSignatureTime));
		}

		/*
		 * b) If step 2 returned the indication INDETERMINATE with the sub-indication
		 * OUT_OF_BOUNDS_NO_POE: If best-signature-time is before the issuance date of the signing
		 * certificate, the process shall return the indication FAILED with the sub-indication NOT_YET_VALID.
		 * Otherwise, the process shall return the indication INDETERMINATE with the sub-indication
		 * OUT_OF_BOUNDS_NO_POE.
		 */
		if (Indication.INDETERMINATE.equals(bsConclusion.getIndication()) && SubIndication.OUT_OF_BOUNDS_NO_POE.equals(bsConclusion.getSubIndication())) {
			item = item.setNextItem(bestSignatureTimeNotBeforeCertificateIssuance(bestSignatureTime));
		}

		/*
		 * c) If step 2 returned INDETERMINATE with the sub-indication CRYPTO_CONSTRAINTS_FAILURE_NO_POE and the
		 * material concerned by this failure is the signature value or a signed attribute: If the algorithm(s)
		 * concerned were still considered reliable at best-signature-time, the process shall continue with step d.
		 * Otherwise, the process shall return the indication INDETERMINATE with the sub-indication
		 * CRYPTO_CONSTRAINTS_FAILURE_NO_POE.
		 */
		if (Indication.INDETERMINATE.equals(bsConclusion.getIndication())
				&& SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(bsConclusion.getSubIndication())) {
			item = item.setNextItem(algorithmReliableAtBestSignatureTime(bestSignatureTime));
		}

		if (Utils.isCollectionNotEmpty(allowedTimestamps)) {
			/*
			 * d) For each time-stamp token remaining in the set of signature time-stamp tokens, the process shall check
			 * the coherence in the values of the times indicated in the time-stamp tokens. They shall be posterior to
			 * the times indicated in any time-stamp token computed on the signed data. The process shall apply the
			 * rules
			 * specified in IETF RFC 3161 [3], clause 2.4.2 regarding the order of time-stamp tokens generated by the
			 * same or different TSAs given the accuracy and ordering fields' values of the TSTInfo field,
			 * unless stated differently by the signature validation constraints. If all the checks end successfully,
			 * the process shall go to the next step. Otherwise the process shall return the indication FAILED with the
			 * sub-indication TIMESTAMP_ORDER_FAILURE.
			 */
			item = item.setNextItem(timestampCoherenceOrder(allowedTimestamps));

			/*
			 * 5) Handling Time-stamp delay: If the validation constraints specify a time-stamp delay:
			 * a) If no signing-time property/attribute is present, the process shall return the indication
			 * INDETERMINATE with the sub-indication SIG_CONSTRAINTS_FAILURE.
			 */
			item = item.setNextItem(signingTimeAttributePresent());

			/*
			 * b) If a signing-time property/attribute is present, the process shall check that the claimed time in the
			 * attribute plus the time-stamp delay is after the best-signature-time. If the check is successful, the
			 * process shall go to the next step. Otherwise, the process shall return the indication FAILED with the
			 * sub-indication SIG_CONSTRAINTS_FAILURE.
			 */
			item = item.setNextItem(timestampDelay(bestSignatureTime));
		}
	}

	private Set<RevocationWrapper> getLinkedRevocationData() {
		Set<RevocationWrapper> result = new HashSet<RevocationWrapper>();
		extractRevocationDataFromCertificateChain(result, currentSignature.getCertificateChainIds());
		List<TimestampWrapper> timestampList = currentSignature.getTimestampList();
		for (TimestampWrapper timestamp : timestampList) {
			extractRevocationDataFromCertificateChain(result, timestamp.getCertificateChainIds());
		}
		return result;
	}

	private void extractRevocationDataFromCertificateChain(Set<RevocationWrapper> result, List<String> certificateChainIds) {
		for (String certificateId : certificateChainIds) {
			CertificateWrapper certificate = diagnosticData.getUsedCertificateById(certificateId);
			if (certificate != null && certificate.getRevocationData() != null) {
				result.addAll(certificate.getRevocationData());
			}
		}
	}

	private Set<TimestampWrapper> filterInvalidTimestamps(List<TimestampWrapper> allTimestamps) {
		Set<TimestampWrapper> result = new HashSet<TimestampWrapper>();
		for (TimestampWrapper timestampWrapper : allTimestamps) {
			boolean foundValidationTSP = false;
			for (XmlValidationProcessTimestamps timestampValidation : timestampValidations) {
				List<XmlConstraint> constraints = timestampValidation.getConstraint();
				for (XmlConstraint tspValidation : constraints) {
					if (Utils.areStringsEqual(timestampWrapper.getId(), tspValidation.getId())) {
						foundValidationTSP = true;
						// PVA : if OK message imprint is validated in SVA of timestamp (depending of constraint.xml)
						if (XmlStatus.OK.equals(tspValidation.getStatus())) {
							result.add(timestampWrapper);
							break;
						}
					}
				}
			}
			if (!foundValidationTSP) {
				logger.warn("Cannot find tsp validation info for tsp " + timestampWrapper.getId());
			}
		}
		return result;
	}

	private ChainItem<XmlValidationProcessLongTermData> isAcceptableBasicSignatureValidation() {
		return new AcceptableBasicSignatureValidationCheck(result, basicSignatureValidation, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> revocationBasicBuildingBlocksValid(XmlBasicBuildingBlocks revocationBBB) {
		return new RevocationBasicBuildingBlocksCheck(result, revocationBBB, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> revocationDateAfterBestSignatureDate(Date bestSignatureTime) {
		CertificateWrapper signingCertificate = diagnosticData.getUsedCertificateById(currentSignature.getSigningCertificateId());
		return new RevocationDateAfterBestSignatureTimeCheck(result, signingCertificate, bestSignatureTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> bestSignatureTimeNotBeforeCertificateIssuance(Date bestSignatureTime) {
		CertificateWrapper signingCertificate = diagnosticData.getUsedCertificateById(currentSignature.getSigningCertificateId());
		return new BestSignatureTimeNotBeforeCertificateIssuanceCheck(result, bestSignatureTime, signingCertificate,
				policy.getBestSignatureTimeBeforeIssuanceDateOfSigningCertificateConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> timestampCoherenceOrder(Set<TimestampWrapper> allowedTimestamps) {
		return new TimestampCoherenceOrderCheck(result, allowedTimestamps, policy.getTimestampCoherenceConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> signingTimeAttributePresent() {
		return new SigningTimeAttributePresentCheck(result, currentSignature, policy.getSigningTimeConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> timestampDelay(Date bestSignatureTime) {
		return new TimestampDelayCheck(result, currentSignature, bestSignatureTime, policy.getTimestampDelaySigningTimePropertyConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> algorithmReliableAtBestSignatureTime(Date bestSignatureTime) {
		return new CryptographicCheck<XmlValidationProcessLongTermData>(result, currentSignature, bestSignatureTime,
				policy.getSignatureCryptographicConstraint(Context.SIGNATURE));
	}

}
