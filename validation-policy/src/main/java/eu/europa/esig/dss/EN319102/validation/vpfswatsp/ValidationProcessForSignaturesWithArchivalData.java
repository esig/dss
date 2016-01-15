package eu.europa.esig.dss.EN319102.validation.vpfswatsp;

import java.util.Date;
import java.util.Map;

import eu.europa.esig.dss.EN319102.bbb.Chain;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks.LongTermValidationCheck;
import eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks.erv.EvidenceRecordValidationCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSignature;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.report.DiagnosticData;

/**
 * 5.6 Validation process for Signatures with Archival Data
 */
public class ValidationProcessForSignaturesWithArchivalData extends Chain<XmlValidationProcessArchivalData> {

	private final XmlConstraintsConclusion validationProcessLongTermData;
	private final SignatureWrapper signature;
	private final Map<String, XmlBasicBuildingBlocks> bbbs;
	private final DiagnosticData diagnosticData;
	private final ValidationPolicy policy;
	private final Date currentTime;

	private final POEExtraction poe = new POEExtraction();

	public ValidationProcessForSignaturesWithArchivalData(XmlSignature signatureAnalysis, SignatureWrapper signature, Map<String, XmlBasicBuildingBlocks> bbbs,
			DiagnosticData diagnosticData, ValidationPolicy policy, Date currentTime) {
		super(new XmlValidationProcessArchivalData());

		this.validationProcessLongTermData = signatureAnalysis.getValidationProcessLongTermData();
		this.signature = signature;
		this.bbbs = bbbs;
		this.diagnosticData = diagnosticData;
		this.policy = policy;
		this.currentTime = currentTime;
	}

	@Override
	protected void initChain() {

		/*
		 * 5.6.3.4
		 * 1) If there is one or more evidence records, the long term validation process shall perform the
		 * evidence record validation process for each of them according to clause 5.6.2.5. If the evidence record
		 * validation process returns PASSED, the SVA shall go to step 6.
		 */
		ChainItem<XmlValidationProcessArchivalData> item = firstItem = evidenceRecordValidationProcess();

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
		item = item.setNextItem(longTermValidation());
		if (isValid(validationProcessLongTermData)) {
			return;
		}

	}

	private ChainItem<XmlValidationProcessArchivalData> evidenceRecordValidationProcess() {
		return new EvidenceRecordValidationCheck(result, signature, bbbs, diagnosticData, poe, policy, currentTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationProcessArchivalData> longTermValidation() {
		return new LongTermValidationCheck(result, validationProcessLongTermData, getFailLevelConstraint());
	}

	private boolean isValid(XmlConstraintsConclusion xmlConstraintConclusion) {
		return xmlConstraintConclusion != null && xmlConstraintConclusion.getConclusion() != null
				&& Indication.VALID.equals(xmlConstraintConclusion.getConclusion().getIndication());
	}

}
