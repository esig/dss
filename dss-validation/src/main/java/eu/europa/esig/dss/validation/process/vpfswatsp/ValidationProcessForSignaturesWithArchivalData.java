/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.vpfswatsp;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalDataTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.sav.SignatureAcceptanceValidation;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.LTALevelTimeStampCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.SignatureAcceptanceValidationResultCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.TLevelTimeStampCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.TimestampDelayCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.EvidenceRecordValidationCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.LongTermAvailabilityAndIntegrityValidationMaterialCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.LongTermValidationCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.PastSignatureValidationCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.TimestampValidationCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.PastSignatureValidation;

import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * 5.6 Validation process for Signatures with Archival Data
 */
public class ValidationProcessForSignaturesWithArchivalData extends Chain<XmlValidationProcessArchivalData> {

	/** Signature validation with long-term data result */
	private final XmlValidationProcessLongTermData validationProcessLongTermData;

	/** Diagnostic Data */
	private final DiagnosticData diagnosticData;

	/** The signature */
	private final SignatureWrapper signature;

	/** Map of BasicBuildingBlocks */
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	/** List of timestamps */
	private final List<XmlTimestamp> xmlTimestamps;

	/** List of evidence records */
	private final List<XmlEvidenceRecord> xmlEvidenceRecords;

	/** Validation policy */
	private final ValidationPolicy policy;

	/** Validation time */
	private final Date currentTime;

	/** The POE container */
	private final POEExtraction poe;

	/** Current validation context */
	private Context context;

	/** Cahced instance of PastSignatureValidation */
	private XmlPSV psvResult;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param signatureAnalysis {@link XmlSignature}
	 * @param diagnosticData {@link DiagnosticData}
	 * @param signature {@link SignatureWrapper}
	 * @param bbbs map of BasicBuildingBlocks
	 * @param policy {@link ValidationPolicy}
	 * @param currentTime {@link Date}
	 * @param poe {@link POEExtraction}
	 */
	public ValidationProcessForSignaturesWithArchivalData(final I18nProvider i18nProvider, final XmlSignature signatureAnalysis,
			final SignatureWrapper signature, final DiagnosticData diagnosticData, final Map<String, XmlBasicBuildingBlocks> bbbs,
			final ValidationPolicy policy, final Date currentTime, final POEExtraction poe) {
		super(i18nProvider, new XmlValidationProcessArchivalData());
		this.validationProcessLongTermData = signatureAnalysis.getValidationProcessLongTermData();
		this.xmlTimestamps = signatureAnalysis.getTimestamps();
		this.xmlEvidenceRecords = signatureAnalysis.getEvidenceRecords();
		this.signature = signature;
		this.diagnosticData = diagnosticData;
		this.bbbs = bbbs;
		this.policy = policy;
		this.currentTime = currentTime;
		this.poe = poe;
	}
	
	@Override
	protected MessageTag getTitle() {
		return MessageTag.VPFSWATSP;
	}

	@Override
	protected void initChain() {

		context = signature.isCounterSignature() ? Context.COUNTER_SIGNATURE : Context.SIGNATURE;

		ChainItem<XmlValidationProcessArchivalData> item = null;

		/*
		 * 5.6.3.4 Processing
		 *
		 * 1) If there is one or more Evidence Records (ERs):
		 *
		 * a) The process shall take the first ER that was not yet processed.
		 * b) The process shall verify this ER according to IETF RFC 4998 [i.9] or IETF RFC 6283 [i.10] taking into
		 * account the following additional requirements when validating a time-stamp token at the time of the
		 * following Archive Timestamp:
		 */
		// steps from b) are performed within ValidationProcessEvidenceRecord
		/*
		 * c) If step b) found the ER to be valid, the process shall add a POE for every object covered by the ER at
		 * signing time value of the initial archive time-stamp.
		 * d) If all ERs have been validated, the process shall continue with step 2).
		 * e) The process shall continue with step 1)a).
		 */
		List<EvidenceRecordWrapper> evidenceRecords = signature.getEvidenceRecords();
		if (Utils.isCollectionNotEmpty(evidenceRecords)) {
			for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
				XmlValidationProcessEvidenceRecord evidenceRecordValidation = getEvidenceRecordValidation(evidenceRecord);
				if (evidenceRecordValidation != null) {

					ChainItem<XmlValidationProcessArchivalData> evidenceRecordValidationConclusive =
							evidenceRecordValidationConclusive(evidenceRecord, evidenceRecordValidation);

					if (item == null) {
						item = firstItem = evidenceRecordValidationConclusive;
					} else {
						item = item.setNextItem(evidenceRecordValidationConclusive);
					}

					if (isValid(evidenceRecordValidation)) {
						poe.extractPOE(evidenceRecord);
					}

				}
			}
		}

		/*
		 * 2) The SVA shall add a POE for each object in the signature at the current time to the set of POEs.
		 */

		// POE provided to the validation

		/*
		 * 3) The SVA shall perform the Validation process for Signatures with Time and Signatures with
		 * Long-Term Validation Material as per clause 5.5 with all the inputs, including the processing
		 * of any signed attributes as specified.
		 *
		 * - If the signature does not contain any attributes for long term availability and integrity of
		 *   validation material, the process shall return the indication/sub-indication and information returned
		 *   by the Validation process for Signatures with Time and Signatures with Long-Term Validation Material.
		 *   Additional information should be included indicating that only the signature-with-time-validation
		 *   process has been performed.
		 *
		 * - If the Validation process for Signatures with Time and Signatures with Long-Term Validation Material
		 *   returned PASSED:
		 * -- If there is no validation constraint mandating the validation of the LTV attributes, the long term
		 *    validation process shall return the indication PASSED.
		 * -- Otherwise, the SVA shall go to step 4.
		 *
		 * - If the Validation process for Signatures with Time and Signatures with Long-Term Validation Material
		 *   returned one of the following indications/sub-indications: INDETERMINATE/REVOKED_NO_POE,
		 *   INDETERMINATE/REVOKED_CA_NO_POE, INDETERMINATE/OUT_OF_BOUNDS_NO_POE,
		 *   INDETERMINATE/OUT_OF_BOUNDS_NOT_REVOKED,
		 *   INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE,
		 *   INDETERMINATE/REVOCATION_OUT_OF_BOUNDS_NO_POE,
		 *   INDETERMINATE/SIG_CONSTRAINTS_FAILURE or INDETERMINATE/TRY_LATER, the long-term
		 *   validation process shall go to the next step.
		 *
		 * - In all other cases, the process shall return the indication/sub-indication and information
		 *   returned by the Validation process for Signatures with Time and Signatures with
		 *   Long-Term Validation Material.
		 */
		if (item == null) {
			item = firstItem = longTermValidation();
		} else {
			item = item.setNextItem(longTermValidation());
		}

		XmlProofOfExistence proofOfExistence = validationProcessLongTermData.getProofOfExistence();
		result.setProofOfExistence(proofOfExistence);

		/*
		 * Return long-term validation process indication
		 */
		if (!ValidationProcessUtils.isAllowedValidationWithLongTermData(validationProcessLongTermData.getConclusion())) {
			return;
		}

		// TODO : this is a workaround, as LTV is not able to recover from NO_CERTIFICATE_CHAIN_FOUND_NO_POE
		if (Indication.INDETERMINATE != validationProcessLongTermData.getConclusion().getIndication() ||
				SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE != validationProcessLongTermData.getConclusion().getSubIndication()) {

			item = item.setNextItem(longTermAvailabilityAndIntegrityValidationMaterial());

			if (!ValidationProcessUtils.isLongTermAvailabilityAndIntegrityMaterialPresent(signature)) {
				return;
			}

		}
		
		/*
		 * 4) The process shall initialize best-signature-time to the best-signature-time returned in step 3)
		 * and add this time as POE for the signature to the set of POEs.
		 */
		POE bestSignatureTime = toPOE(proofOfExistence);
		poe.addSignaturePOE(signature, bestSignatureTime);

		/*
		 * 5) If there is at least one time-stamp attribute:
		 *
		 * a) The long term validation process shall select the newest time-stamp that has not been processed and
		 * perform the time-stamp validation, as per clause 5.4.
		 */
		List<TimestampWrapper> timestampsList = signature.getTimestampList();
		if (Utils.isCollectionNotEmpty(timestampsList)) {
			timestampsList.sort(Comparator.comparing(TimestampWrapper::getProductionTime).reversed());

			for (TimestampWrapper newestTimestamp : timestampsList) {
				XmlBasicBuildingBlocks bbbTsp = bbbs.get(newestTimestamp.getId());
				XmlValidationProcessArchivalDataTimestamp timestampValidation = getTimestampValidation(newestTimestamp);
				if (bbbTsp != null && timestampValidation != null) {

					// steps b) and c) are part of ValidationProcessForTimestampsWithArchivalData

					item = item.setNextItem(timestampValidationConclusive(newestTimestamp, timestampValidation));

					/*
					 * d) In all other cases:
					 * - If no specific constraints mandating the validity of the attribute are specified in the
					 * validation constraints, the SVA shall ignore the attribute and shall continue with step 5 using
					 * the next timestamp attribute.
					 * - Otherwise, the process shall fail with the returned indication/sub-indication and associated
					 * explanations.
					 */

				}
				
			/*
			 * e) If all time-stamp attributes have been processed, the SVA shall continue with step 6.
			 * Otherwise, the SVA shall continue with step 5a.
			 */
			}
			
		}

		/*
		 * Performs optional checks allowing to fail validation process in case of a missing timestamp
		 */
		item = item.setNextItem(tLevelTimeStamp());

		item = item.setNextItem(ltaLevelTimeStamp());

		/*
		 * 6) The SVA shall determine from the set of POEs the earliest time the existence of the signature
		 * can be proven and set best-signature-time to this new determined time.
		 */
		bestSignatureTime = poe.getLowestPOE(signature.getId());
		result.setProofOfExistence(toXmlProofOfExistence(bestSignatureTime));

		if (isValid(validationProcessLongTermData)) {
			// skip past signature validation when basic validation succeeded
			return;
		}

		/*
		 * 7) Past signature validation: the long term validation process shall perform the past signature validation
		 * process with the following inputs: the signature, the status indication/sub-indication returned in step 2,
		 * the signing certificate, the X.509 validation parameters, certificate validation data, chain constraints,
		 * cryptographic constraints, the set of POEs and best-signature-time. If it returns PASSED the long term
		 * validation process shall go to the next step. Otherwise, the long term validation process shall return
		 * the indication/sub-indication and associated explanations returned from the past signature validation process.
		 */
		XmlBasicBuildingBlocks sigBBB = bbbs.get(signature.getId());
		PastSignatureValidation psv = new PastSignatureValidation(i18nProvider, signature, bbbs,
				validationProcessLongTermData.getConclusion(), poe, currentTime, policy, context);
		psvResult = psv.execute();
		sigBBB.setPSV(psvResult);
		enrichBBBWithPSVConclusion(sigBBB, psvResult);

		item = item.setNextItem(pastSignatureValidation(psvResult));

		/*
		 * 8) Handling time-stamp delay: If the signature contains a signature time stamp token and the validation
		 * specify a time stamp delay:
		 * a) If no signing time property/attribute is present, the process shall return the indication INDETERMINATE
		 *    with the sub indication SIG_CONSTRAINTS_FAILURE.
		 * b) If a signing time property/attribute is present, the process shall check that the claimed time in the
		 *    attribute plus the time stamp delay is after the best-signature-time determined in step 6) above. If
		 *    the check is successful, the process shall go to the next step. Otherwise, the process shall return
		 *    the indication INDETERMINATE with the sub indication SIG_CONSTRAINTS_FAILURE.
		 */
		item = item.setNextItem(timestampDelay(bestSignatureTime.getTime()));

		/*
		 * 9) The SVA shall perform the Signature Acceptance Validation process as per clause 5.2.8 with the following
		 * inputs:
		 * a) The Signed Data Object(s).
		 * b) The time determined in step 7 as the validation time parameter.
		 * c) The Cryptographic Constraints.
		 *
		 * If the Signature Acceptance Validation process returns PASSED, the SVA shall go to the next step. Otherwise,
		 * the SVA shall return the indication and sub-indication returned by the Signature Acceptance Validation
		 * Process.
		 */
		item = item.setNextItem(signatureIsAcceptable(bestSignatureTime.getTime(), context));

		/*
		 * 10) Data extraction: the SVA shall return the success indication PASSED. In addition, the SVA should return
		 * additional information extracted from the signature and/or used by the intermediate steps. In particular, the
		 * SVA should return the best-signature-time determined in step 6) as well as intermediate results such as the
		 * validation results of any time-stamp token.
		 */
		
		/*
		 * Otherwise,
		 * the SVA shall return the indication and sub-indication returned by the Signature Acceptance Validation Process
		 */

	}

	private ChainItem<XmlValidationProcessArchivalData> pastSignatureValidation(XmlPSV xmlPSV) {
		return new PastSignatureValidationCheck(i18nProvider, result, signature, xmlPSV, getFailLevelRule());
	}

	private ChainItem<XmlValidationProcessArchivalData> longTermValidation() {
		return new LongTermValidationCheck(i18nProvider, result, validationProcessLongTermData, getFailLevelRule());
	}

	private ChainItem<XmlValidationProcessArchivalData> longTermAvailabilityAndIntegrityValidationMaterial() {
		LevelRule constraint = isValid(validationProcessLongTermData) ? getInfoLevelRule() : getFailLevelRule();
		return new LongTermAvailabilityAndIntegrityValidationMaterialCheck(i18nProvider, result, signature, validationProcessLongTermData, constraint);
	}

	private ChainItem<XmlValidationProcessArchivalData> timestampValidationConclusive(
			TimestampWrapper timestampWrapper, XmlValidationProcessArchivalDataTimestamp timestampValidationResult) {
		return new TimestampValidationCheck<>(i18nProvider, result, timestampWrapper,
				timestampValidationResult, getTimestampValidationConstraintLevel());
	}

	private ChainItem<XmlValidationProcessArchivalData> evidenceRecordValidationConclusive(
			EvidenceRecordWrapper evidenceRecordWrapper, XmlValidationProcessEvidenceRecord erValidationResult) {
		return new EvidenceRecordValidationCheck<>(i18nProvider, result, evidenceRecordWrapper,
				erValidationResult, getEvidenceRecordValidationConstraintLevel());
	}

	private LevelRule getTimestampValidationConstraintLevel() {
		LevelRule constraint = policy.getTimestampValidConstraint();
		if (constraint == null) {
			constraint = getWarnLevelRule();
		}
		return constraint;
	}

	private LevelRule getEvidenceRecordValidationConstraintLevel() {
		LevelRule constraint = policy.getEvidenceRecordValidConstraint();
		if (constraint == null) {
			constraint = getWarnLevelRule();
		}
		return constraint;
	}

	private ChainItem<XmlValidationProcessArchivalData> tLevelTimeStamp() {
		LevelRule constraint = policy.getTLevelTimeStampConstraint(context);
		return new TLevelTimeStampCheck<>(i18nProvider, result, signature, bbbs, xmlTimestamps, constraint);
	}

	private ChainItem<XmlValidationProcessArchivalData> ltaLevelTimeStamp() {
		LevelRule constraint = policy.getLTALevelTimeStampConstraint(context);
		return new LTALevelTimeStampCheck<>(i18nProvider, result, signature, bbbs, xmlTimestamps, constraint);
	}

	private ChainItem<XmlValidationProcessArchivalData> timestampDelay(Date bestSignatureTime) {
		return new TimestampDelayCheck<>(i18nProvider, result, signature, bestSignatureTime, policy.getTimestampDelayConstraint());
	}

	private ChainItem<XmlValidationProcessArchivalData> signatureIsAcceptable(Date bestSignatureTime, Context context) {
		SignatureAcceptanceValidation sav = new SignatureAcceptanceValidation(
				i18nProvider, diagnosticData, bestSignatureTime, signature, context, bbbs, policy);
		XmlSAV savResult = sav.execute();
		return new SignatureAcceptanceValidationResultCheck<>(i18nProvider, result, savResult, getFailLevelRule());
	}

	private void enrichBBBWithPSVConclusion(XmlBasicBuildingBlocks bbb, XmlPSV psv) {
		XmlConclusion bbbConclusion = bbb.getConclusion();
		XmlConclusion psvConclusion = psv.getConclusion();
		bbbConclusion.setIndication(psvConclusion.getIndication());
		bbbConclusion.setSubIndication(psvConclusion.getSubIndication());
		bbbConclusion.getErrors().addAll(psvConclusion.getErrors());
		bbbConclusion.getWarnings().addAll(psvConclusion.getWarnings());
		bbbConclusion.getInfos().addAll(psvConclusion.getInfos());
	}

	private XmlProofOfExistence toXmlProofOfExistence(POE poe) {
		XmlProofOfExistence xmlPoe = new XmlProofOfExistence();
		xmlPoe.setTime(poe.getTime());
		xmlPoe.setTimestampId(poe.getPOEProviderId());
		return xmlPoe;
	}

	private POE toPOE(XmlProofOfExistence xmlProofOfExistence) {
		String timestampId = xmlProofOfExistence.getTimestampId();
		if (timestampId != null) {
			for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
				if (timestampId.equals(timestamp.getId())) {
					return new TimestampPOE(timestamp);
				}
			}
			// Should not happen, as current revision of the standard does not handle ERs within LTV process.
			for (EvidenceRecordWrapper evidenceRecordWrapper : diagnosticData.getEvidenceRecords()) {
				if (timestampId.equals(evidenceRecordWrapper.getId())) {
					return new EvidenceRecordPOE(evidenceRecordWrapper);
				}
			}
		}
		return new POE(xmlProofOfExistence.getTime());
	}

	private XmlValidationProcessArchivalDataTimestamp getTimestampValidation(TimestampWrapper newestTimestamp) {
		for (XmlTimestamp xmlTimestamp : xmlTimestamps) {
			if (Utils.areStringsEqual(xmlTimestamp.getId(), newestTimestamp.getId())) {
				return xmlTimestamp.getValidationProcessArchivalDataTimestamp();
			}
		}
		return null;
	}

	private XmlValidationProcessEvidenceRecord getEvidenceRecordValidation(EvidenceRecordWrapper evidenceRecord) {
		for (XmlEvidenceRecord xmlEvidenceRecord : xmlEvidenceRecords) {
			if (Utils.areStringsEqual(xmlEvidenceRecord.getId(), evidenceRecord.getId())) {
				return xmlEvidenceRecord.getValidationProcessEvidenceRecord();
			}
		}
		return null;
	}

	@Override
	protected void collectMessages(XmlConclusion conclusion, XmlConstraint constraint) {
		if (XmlBlockType.TST.equals(constraint.getBlockType()) && policy.getTimestampValidConstraint() == null) {
			// skip propagating of validation messages for TSTs in default processing
		} else if (XmlBlockType.LTA == constraint.getBlockType()) {
			// skip LTA data missing message
		} else {
			super.collectMessages(conclusion, constraint);
		}
	}

	@Override
	protected void collectAdditionalMessages(XmlConclusion conclusion) {
		if (!ValidationProcessUtils.isAllowedValidationWithLongTermData(validationProcessLongTermData.getConclusion())
				|| !ValidationProcessUtils.isLongTermAvailabilityAndIntegrityMaterialPresent(signature)) {
			conclusion.getWarnings().addAll(validationProcessLongTermData.getConclusion().getWarnings());
			conclusion.getInfos().addAll(validationProcessLongTermData.getConclusion().getInfos());
		}
		if (psvResult != null) {
			if (!isValid(psvResult) && psvResult.getConclusion().getSubIndication() != validationProcessLongTermData.getConclusion().getSubIndication()) {
				conclusion.getErrors().addAll(psvResult.getConclusion().getErrors());
			}
			conclusion.getWarnings().addAll(psvResult.getConclusion().getWarnings());
			conclusion.getInfos().addAll(psvResult.getConclusion().getInfos());
		}
	}

}
