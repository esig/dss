package eu.europa.esig.dss.EN319102.validation.vpfltvd;

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.EN319102.bbb.Chain;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.validation.vpfltvd.checks.AcceptableBasicSignatureValidationCheck;
import eu.europa.esig.dss.EN319102.validation.vpfltvd.checks.BestSignatureTimeBeforeIssuanceDateOfSigningCertificateCheck;
import eu.europa.esig.dss.EN319102.validation.vpfltvd.checks.RevocationBasicBuildingBlocksCheck;
import eu.europa.esig.dss.EN319102.validation.vpfltvd.checks.RevocationDateAfterBestSignatureTimeCheck;
import eu.europa.esig.dss.EN319102.validation.vpfltvd.checks.SigningCertificateValidityAtBestSignatureTimeCheck;
import eu.europa.esig.dss.EN319102.validation.vpfltvd.checks.SigningTimeAttributePresentCheck;
import eu.europa.esig.dss.EN319102.validation.vpfltvd.checks.TimestampCoherenceOrderCheck;
import eu.europa.esig.dss.EN319102.validation.vpfltvd.checks.TimestampDelayCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.validation.CertificateWrapper;
import eu.europa.esig.dss.validation.RevocationWrapper;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.TimestampWrapper;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;
import eu.europa.esig.jaxb.policy.TimeConstraint;
import eu.europa.esig.jaxb.policy.TimeUnit;

/**
 * 5.5 Validation process for Signatures with Time and Signatures with Long-Term Validation Data
 */
public class ValidationProcessForSignaturesWithLongTermValidationData extends Chain<XmlValidationProcessLongTermData> {

	private static final Logger logger = LoggerFactory.getLogger(ValidationProcessForSignaturesWithLongTermValidationData.class);

	private final XmlConstraintsConclusion basicSignatureValidation;
	private final XmlConstraintsConclusion timestampValidation;

	private final DiagnosticData diagnosticData;
	private final SignatureWrapper currentSignature;
	private final Set<TimestampWrapper> timestamps;
	private final Set<RevocationWrapper> revocationData;
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	private final Date currentDate;

	public ValidationProcessForSignaturesWithLongTermValidationData(XmlConstraintsConclusion basicSignatureValidation,
			XmlConstraintsConclusion timestampValidation, DiagnosticData diagnosticData, SignatureWrapper currentSignature, Set<TimestampWrapper> timestamps,
			Set<RevocationWrapper> revocationData, Map<String, XmlBasicBuildingBlocks> bbbs, Date currentDate) {
		super(new XmlValidationProcessLongTermData());

		this.basicSignatureValidation = basicSignatureValidation;
		this.timestampValidation = timestampValidation;

		this.diagnosticData = diagnosticData;
		this.currentSignature = currentSignature;
		this.timestamps = timestamps;
		this.revocationData = revocationData;
		this.bbbs = bbbs;
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

		if (CollectionUtils.isNotEmpty(revocationData)) {
			for (RevocationWrapper revocation : revocationData) {
				XmlBasicBuildingBlocks revocationBBB = bbbs.get(revocation.getId());
				if (revocationBBB != null) {
					item = item.setNextItem(revocationBasicBuildingBlocksValid(revocationBBB));
				}
			}
		}

		/*
		 * 3) Signature time-stamp validation:
		 * a) For each time-stamp token in the set of signature time-stamp tokens, the process shall check that the
		 * message imprint has been generated according to the corresponding signature format specification
		 * verification. If the verification fails, the process shall remove the token from the set.
		 */
		Set<TimestampWrapper> allowedTimestamps = filterInvalidMessageImprint(timestamps);

		/*
		 * b) Time-stamp token validation: For each time-stamp token remaining in the set of signature time-stamp
		 * tokens, the process shall perform the time-stamp validation process as per clause 5.4:
		 * 
		 * If PASSED is returned and if the returned generation time is before best-signature-time, the process
		 * shall set best-signature-time to this date and shall try the next token.
		 */
		for (TimestampWrapper timestampWrapper : allowedTimestamps) {
			List<XmlConstraint> constraints = timestampValidation.getConstraints();
			boolean foundValidationTSP = false;
			for (XmlConstraint tspValidation : constraints) {
				if (StringUtils.equals(timestampWrapper.getId(), tspValidation.getId())) {
					foundValidationTSP = true;
					Date productionTime = timestampWrapper.getProductionTime();
					if (XmlStatus.OK.equals(tspValidation.getStatus()) && productionTime.before(bestSignatureTime)) {
						bestSignatureTime = productionTime;
						break;
					}
				}
			}
			if (!foundValidationTSP) {
				logger.warn("Cannot find tsp validation info for tsp " + timestampWrapper.getId());
			}
		}

		/*
		 * 4) Comparing times:
		 * a) If step 2 returned the indication INDETERMINATE with the sub-indication REVOKED_NO_POE: If the
		 * returned revocation time is posterior to best-signature-time, the process shall perform step 4d. Otherwise,
		 * the process shall return the indication INDETERMINATE with the sub-indication REVOKED_NO_POE.
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
			item = item.setNextItem(bestSignatureTimeBeforeIssuanceDateOfSigningCertificate(bestSignatureTime));
			item = item.setNextItem(signingCertificateValidityAtBestSignatureTime(bestSignatureTime)); // otherwise
		}

		/*
		 * c) If step 2 returned INDETERMINATE with the sub-indication CRYPTO_CONSTRAINTS_FAILURE_NO_POE and the
		 * material concerned by this failure is the signature value or a signed attribute: If the algorithm(s)
		 * concerned were still considered reliable at best-signature-time, the process shall continue with step d.
		 * Otherwise, the process shall return the indication INDETERMINATE with the sub-indication
		 * CRYPTO_CONSTRAINTS_FAILURE_NO_POE.
		 */
		// TODO expired algorithm to be tested against bestSignatureTime
		// if (Indication.INDETERMINATE.equals(bsConclusion.getIndication())
		// && SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(bsConclusion.getSubIndication())) {
		// item = item.setNextItem(algorithmReliableAtBestSignatureTime(bestSignatureTime));
		// }

		/*
		 * d) For each time-stamp token remaining in the set of signature time-stamp tokens, the process shall check
		 * the coherence in the values of the times indicated in the time-stamp tokens. They shall be posterior to the
		 * times indicated in any time-stamp token computed on the signed data. The process shall apply the rules
		 * specified in IETF RFC 3161 [3], clause 2.4.2 regarding the order of time-stamp tokens generated by the
		 * same or different TSAs given the accuracy and ordering fields' values of the TSTInfo field,
		 * unless stated differently by the signature validation constraints. If all the checks end successfully, the
		 * process shall go to the next step. Otherwise the process shall return the indication FAILED with the
		 * sub-indication TIMESTAMP_ORDER_FAILURE.
		 */
		item = item.setNextItem(timestampCoherenceOrder(allowedTimestamps));

		/*
		 * 5) Handling Time-stamp delay: If the validation constraints specify a time-stamp delay:
		 * a) If no signing-time property/attribute is present, the process shall return the indication INDETERMINATE
		 * with the sub-indication SIG_CONSTRAINTS_FAILURE.
		 */
		item = item.setNextItem(signingTimeAttributePresent());

		/*
		 * b) If a signing-time property/attribute is present, the process shall check that the claimed time in the
		 * attribute plus the time-stamp delay is after the best-signature-time. If the check is successful, the process
		 * shall go to the next step. Otherwise, the process shall return the indication FAILED with the sub-indication
		 * SIG_CONSTRAINTS_FAILURE.
		 */
		item = item.setNextItem(timestampDelay(bestSignatureTime));

	}

	private ChainItem<XmlValidationProcessLongTermData> isAcceptableBasicSignatureValidation() {
		return new AcceptableBasicSignatureValidationCheck(result, basicSignatureValidation, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> revocationBasicBuildingBlocksValid(XmlBasicBuildingBlocks revocationBBB) {
		return new RevocationBasicBuildingBlocksCheck(result, revocationBBB, getFailLevelConstraint());
	}

	private Set<TimestampWrapper> filterInvalidMessageImprint(Set<TimestampWrapper> allTimestamps) {
		Set<TimestampWrapper> result = new HashSet<TimestampWrapper>();
		for (TimestampWrapper tsp : allTimestamps) {
			if (tsp.isMessageImprintDataFound() && tsp.isMessageImprintDataIntact()) {
				result.add(tsp);
			} else {
				logger.info("Timestamp " + tsp.getId() + " is skipped");
			}
		}
		return result;
	}

	private ChainItem<XmlValidationProcessLongTermData> revocationDateAfterBestSignatureDate(Date bestSignatureTime) {
		CertificateWrapper signingCertificate = diagnosticData.getUsedCertificateById(currentSignature.getSigningCertificateId());
		return new RevocationDateAfterBestSignatureTimeCheck(result, signingCertificate, bestSignatureTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> bestSignatureTimeBeforeIssuanceDateOfSigningCertificate(Date bestSignatureTime) {
		CertificateWrapper signingCertificate = diagnosticData.getUsedCertificateById(currentSignature.getSigningCertificateId());
		return new BestSignatureTimeBeforeIssuanceDateOfSigningCertificateCheck(result, signingCertificate, bestSignatureTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> signingCertificateValidityAtBestSignatureTime(Date bestSignatureTime) {
		CertificateWrapper signingCertificate = diagnosticData.getUsedCertificateById(currentSignature.getSigningCertificateId());
		return new SigningCertificateValidityAtBestSignatureTimeCheck(result, signingCertificate, bestSignatureTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> timestampCoherenceOrder(Set<TimestampWrapper> allowedTimestamps) {
		return new TimestampCoherenceOrderCheck(result, allowedTimestamps, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> signingTimeAttributePresent() {
		return new SigningTimeAttributePresentCheck(result, currentSignature, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> timestampDelay(Date bestSignatureTime) {
		return new TimestampDelayCheck(result, currentSignature, bestSignatureTime, getFailTimeConstraint());
	}

	// TODO uses validation policy
	private LevelConstraint getFailLevelConstraint() {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		return constraint;
	}

	// TODO uses validation policy
	private TimeConstraint getFailTimeConstraint() {
		TimeConstraint constraint = new TimeConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.setUnit(TimeUnit.DAYS);
		constraint.setValue(1);
		return constraint;
	}

}
