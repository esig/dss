package eu.europa.esig.dss.validation.process.vpfswatsp;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlPSV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSignature;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessTimestamps;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AttributeValue;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.LongTermValidationCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.PastSignatureValidationCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.PastSignatureValidation;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;

/**
 * 5.6 Validation process for Signatures with Archival Data
 */
public class ValidationProcessForSignaturesWithArchivalData extends Chain<XmlValidationProcessArchivalData> {

	private static final Logger logger = LoggerFactory.getLogger(ValidationProcessForSignaturesWithArchivalData.class);

	private final XmlConstraintsConclusion validationProcessLongTermData;
	private final List<XmlValidationProcessTimestamps> validationProcessTimestamps;
	private final SignatureWrapper signature;
	private final DiagnosticData diagnosticData;
	private final Map<String, XmlBasicBuildingBlocks> bbbs;
	private final ValidationPolicy policy;
	private final Date currentTime;

	private final POEExtraction poe = new POEExtraction();

	public ValidationProcessForSignaturesWithArchivalData(XmlSignature signatureAnalysis, SignatureWrapper signature, DiagnosticData diagnosticData,
			Map<String, XmlBasicBuildingBlocks> bbbs, ValidationPolicy policy, Date currentTime) {
		super(new XmlValidationProcessArchivalData());

		this.validationProcessLongTermData = signatureAnalysis.getValidationProcessLongTermData();
		this.validationProcessTimestamps = signatureAnalysis.getValidationProcessTimestamps();
		this.signature = signature;
		this.diagnosticData = diagnosticData;
		this.bbbs = bbbs;
		this.policy = policy;
		this.currentTime = currentTime;
	}

	@Override
	protected void initChain() {

		Context currentContext = Context.SIGNATURE;
		if (AttributeValue.COUNTERSIGNATURE.equals(signature.getType())) {
			currentContext = Context.COUNTER_SIGNATURE;
		}

		/*
		 * 5.6.3.4
		 * 1) If there is one or more evidence records, the long term validation process shall perform the
		 * evidence record validation process for each of them according to clause 5.6.2.5. If the evidence record
		 * validation process returns PASSED, the SVA shall go to step 6.
		 */
		// not supported

		/*
		 * 2) POE initialization: the long term validation process shall add a POE for each object in the signature
		 * at the current time to the set of POEs.
		 * NOTE 1: The set of POE in the input may have been initialized from external sources (e.g. provided from
		 * an external archiving system). These POEs will be used without additional processing.
		 */
		poe.init(diagnosticData, currentTime);

		/*
		 * 3) The long term validation process shall perform the validation process for Signatures with Time as per
		 * clause 5.5 with all the inputs, including the processing of any signed attributes as specified.
		 * - If the validation outputs PASSED:
		 * -- If there is no validation constraint mandating the validation of the LTV attributes, the long term
		 * validation process shall return the indication PASSED.
		 * -- Otherwise, the SVA shall go to step 4.
		 * - If the validation outputs one of the following indications/sub-indications:
		 * INDETERMINATE/REVOKED_NO_POE, INDETERMINATE/REVOKED_CA_NO_POE,
		 * INDETERMINATE/OUT_OF_BOUNDS_NO_POE or
		 * INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE, the long term validation process
		 * shall go to the next step.
		 * - In all other cases, the long term validation process shall fail with returned code and information.
		 */
		ChainItem<XmlValidationProcessArchivalData> item = firstItem = longTermValidation();
		if (isValid(validationProcessLongTermData)) {
			return;
		}

		/*
		 * 4) If there is at least one time-stamp attribute:
		 * a) The long term validation process shall select the newest time-stamp that has not been processed and
		 * perform the time-stamp validation, as per clause 5.4.
		 */
		List<TimestampWrapper> timestampsList = signature.getTimestampList();
		if (Utils.isCollectionNotEmpty(timestampsList)) {
			Collections.sort(timestampsList, new TimestampComparator());
			for (TimestampWrapper newestTimestamp : timestampsList) {
				XmlBasicBuildingBlocks bbbTsp = bbbs.get(newestTimestamp.getId());
				XmlConstraintsConclusion timestampValidation = getTimestampValidation(newestTimestamp);
				if ((timestampValidation != null) && (bbbTsp != null)) {

					/*
					 * b) If PASSED is returned and the cryptographic hash function used in the time-stamp
					 * (messageImprint.hashAlgorithm) is considered reliable at the generation time of the time-stamp,
					 * the long term validation process shall perform the POE extraction process with the signature, the
					 * time-stamp and the cryptographic constraints as inputs. The long term validation process shall
					 * add the returned POEs to the set of POEs.
					 */
					if (isValid(timestampValidation)/* TODO && crypto */) {
						poe.extractPOE(newestTimestamp, diagnosticData);
					}
					/*
					 * c) Otherwise, the long term validation process shall perform past signature validation process
					 * with the following inputs: the time-stamp, the indication/sub-indication returned by the
					 * time-stamp
					 * validation process, the TSA's certificate, the X.509 validation parameters, X.509 validation
					 * constraints, cryptographic constraints and the set of POEs.
					 */
					else {
						PastSignatureValidation psv = new PastSignatureValidation(newestTimestamp, diagnosticData, bbbTsp, poe, currentTime, policy,
								Context.TIMESTAMP);
						XmlPSV psvResult = psv.execute();
						bbbTsp.setPSV(psvResult);

						/*
						 * If it returns PASSED and the cryptographic hash function used in the time-stamp is considered
						 * reliable at the generation time of the time-stamp, the long term validation process shall
						 * perform the POE extraction process and shall add the returned POEs to the set of POEs
						 * continue with
						 * step 4 using the next timestamp attribute.
						 */
						if (isValid(psvResult)/* TODO && crypto */) {
							poe.extractPOE(newestTimestamp, diagnosticData);
						}
					}

					/*
					 * In all other cases:
					 * - If no specific constraints mandating the validity of the attribute are specified in the
					 * validation constraints, the SVA shall ignore the attribute and shall continue with step 4 using
					 * the next timestamp attribute.
					 * - Otherwise, the process shall fail with the returned indication/sub-indication and associated
					 * explanations.
					 * d) If all time-stamp attributes have been processed, the SVA shall continue with step 5.
					 * Otherwise, the SVA shall continue with step 4b.
					 */

				} else { // timestampValidation is null
					logger.error("No timestamp validation found for timestamp " + newestTimestamp.getId());
				}
			}
		}

		/*
		 * 5) Past signature validation: the long term validation process shall perform the past signature validation
		 * process with the following inputs: the signature, the status indication/sub-indication returned in step 2,
		 * the signing certificate, the X.509 validation parameters, certificate validation data, chain constraints,
		 * cryptographic constraints and the set of POEs. If it returns PASSED the long term validation process shall go
		 * to the next step. Otherwise, the long term validation process shall return the indication/sub-indication and
		 * associated explanations returned from the past signature validation process.
		 */
		item = item.setNextItem(pastSignatureValidation(currentContext));

		/*
		 * 6) Data extraction: the SVA shall return the success indication PASSED. In addition, the long term validation
		 * process should return additional information extracted from the signature and/or used by the intermediate
		 * steps. In particular, the long term validation process should return intermediate results such as the
		 * validation results of any time-stamp token.
		 * NOTE 5: What the DA does with this information is out of the scope of the present document.
		 */

	}

	private ChainItem<XmlValidationProcessArchivalData> pastSignatureValidation(Context currentContext) {
		XmlBasicBuildingBlocks bbbSig = bbbs.get(signature.getId());
		return new PastSignatureValidationCheck(result, signature, diagnosticData, bbbSig, poe, currentTime, policy, currentContext, getFailLevelConstraint());
	}

	private XmlConstraintsConclusion getTimestampValidation(TimestampWrapper newestTimestamp) {
		for (XmlValidationProcessTimestamps tspValidation : validationProcessTimestamps) {
			if (Utils.areStringsEqual(tspValidation.getId(), newestTimestamp.getId())) {
				return tspValidation;
			}
		}
		return null;
	}

	private ChainItem<XmlValidationProcessArchivalData> longTermValidation() {
		return new LongTermValidationCheck(result, validationProcessLongTermData, getFailLevelConstraint());
	}

	private boolean isValid(XmlConstraintsConclusion xmlConstraintConclusion) {
		return xmlConstraintConclusion != null && xmlConstraintConclusion.getConclusion() != null
				&& Indication.PASSED.equals(xmlConstraintConclusion.getConclusion().getIndication());
	}

}
