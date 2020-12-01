/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.vpfswatsp;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.MessageImprintDigestAlgorithmValidation;
import eu.europa.esig.dss.validation.process.bbb.sav.SignatureAcceptanceValidation;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.SignatureAcceptanceValidationResultCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.LongTermValidationCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.PastSignatureValidationCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.PastTimestampValidation;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.PastSignatureValidation;

import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * 5.6 Validation process for Signatures with Archival Data
 */
public class ValidationProcessForSignaturesWithArchivalData extends Chain<XmlValidationProcessArchivalData> {

	private final XmlValidationProcessLongTermData validationProcessLongTermData;
	private final List<XmlTimestamp> xmlTimestamps;
	private final SignatureWrapper signature;
	private final DiagnosticData diagnosticData;
	private final Map<String, XmlBasicBuildingBlocks> bbbs;
	private final ValidationPolicy policy;
	private final Date currentTime;

	private final POEExtraction poe = new POEExtraction();

	public ValidationProcessForSignaturesWithArchivalData(I18nProvider i18nProvider, XmlSignature signatureAnalysis, SignatureWrapper signature, 
			DiagnosticData diagnosticData, Map<String, XmlBasicBuildingBlocks> bbbs, ValidationPolicy policy, Date currentTime) {
		super(i18nProvider, new XmlValidationProcessArchivalData());
		this.validationProcessLongTermData = signatureAnalysis.getValidationProcessLongTermData();
		this.xmlTimestamps = signatureAnalysis.getTimestamp();
		this.signature = signature;
		this.diagnosticData = diagnosticData;
		this.bbbs = bbbs;
		this.policy = policy;
		this.currentTime = currentTime;
	}
	
	@Override
	protected MessageTag getTitle() {
		return MessageTag.VPFSWATSP;
	}

	@Override
	protected void initChain() {

		Context currentContext = Context.SIGNATURE;
		if (signature.isCounterSignature()) {
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
		result.setProofOfExistence(validationProcessLongTermData.getProofOfExistence());
		if (isValid(validationProcessLongTermData)) {
			return;
		}
		
		/*
		 * 4) The process shall add the best-signature-time returned in step 3 
		 * as POE for the signature to the set of POEs.
		 */
		XmlProofOfExistence signatureProofOfExistence = validationProcessLongTermData.getProofOfExistence();
		poe.addSignaturePOE(signature, toPOE(signatureProofOfExistence));

		/*
		 * 5) If there is at least one time-stamp attribute:
		 * a) The long term validation process shall select the newest time-stamp that has not been processed and
		 * perform the time-stamp validation, as per clause 5.4.
		 */
		List<TimestampWrapper> timestampsList = signature.getTimestampList();
		if (Utils.isCollectionNotEmpty(timestampsList)) {
			XmlConclusion latestConclusion = null;

			timestampsList.sort(Comparator.comparing(TimestampWrapper::getProductionTime).reversed());
			for (TimestampWrapper newestTimestamp : timestampsList) {
				XmlBasicBuildingBlocks bbbTsp = bbbs.get(newestTimestamp.getId());
				XmlConstraintsConclusion timestampValidation = getTimestampValidation(newestTimestamp);
				if ((timestampValidation != null) && (bbbTsp != null)) {
					latestConclusion = timestampValidation.getConclusion();

					MessageImprintDigestAlgorithmValidation messageImprintValidation = timestampDigestAlgorithmValidation(newestTimestamp);
					XmlSAV davResult = messageImprintValidation.execute();
					
					/*
					 * b) If PASSED is returned and the cryptographic hash function used in the time-stamp
					 * (messageImprint.hashAlgorithm) is considered reliable at the generation time of the time-stamp,
					 * the long term validation process shall perform the POE extraction process with the signature, the
					 * time-stamp and the cryptographic constraints as inputs. The long term validation process shall
					 * add the returned POEs to the set of POEs.
					 */
					if (isValid(timestampValidation) && isValid(davResult)) {
						poe.extractPOE(newestTimestamp);
					}
					
					/*
					 * c) If the output of the validation is INDETERMINATE/REVOKED_NO_POE,
					 * INDETERMINATE/REVOKED_CA_NO_POE, INDETERMINATE/OUT_OF_BOUNDS_NO_POE or
					 * INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE, the SVA shall perform past
					 * signature validation process (as per clause 5.6.2.4) with the following inputs: the time-stamp, the
					 * indication/sub-indication returned by the time-stamp validation process in step 5a, the TSA's certificate,
					 * the X.509 validation parameters, X.509 validation constraints, cryptographic constraints, certificate
					 * validation data and the set of POEs. 
					 */
					else if (shouldPerformPastSignatureValidationProcess(latestConclusion)) {
						
						PastSignatureValidation psv = new PastSignatureValidation(i18nProvider, newestTimestamp, bbbs, poe, currentTime, 
								policy, Context.TIMESTAMP);
						XmlPSV psvResult = psv.execute();
						bbbTsp.setPSV(psvResult);
						bbbTsp.setConclusion(psvResult.getConclusion());

						/*
						 * If it returns PASSED and the cryptographic hash function used in the time-stamp is considered
						 * reliable at the generation time of the time-stamp, the long term validation process shall
						 * perform the POE extraction process and shall add the returned POEs to the set of POEs
						 * continue with
						 * step 5a using the next timestamp attribute.
						 */
						if (isValid(psvResult) && isValid(davResult)) {
							poe.extractPOE(newestTimestamp);
						}
						
					}
					/*
					 * d) In all other cases:
					 * - If no specific constraints mandating the validity of the attribute are specified in the
					 * validation constraints, the SVA shall ignore the attribute and shall continue with step 5 using
					 * the next timestamp attribute.
					 */
					else {
						// continue;
					}
				}
				
				/*
				 * - Otherwise, the process shall fail with the returned indication/sub-indication and associated
				 * explanations.
				 */
				else { // timestampValidation is null
					result.setConclusion(latestConclusion);
					break;
				}
				
			/*
			 * e) If all time-stamp attributes have been processed, the SVA shall continue with step 6.
			 * Otherwise, the SVA shall continue with step 5a.
			 */
			}
			
			// add past timestamp validation information in the proper order
			for (TimestampWrapper timestamp : Utils.reverseList(timestampsList)) {
				XmlBasicBuildingBlocks bbbTsp = bbbs.get(timestamp.getId());
				if (bbbTsp.getPSV() != null) {
					item = item.setNextItem(pastTimestampValidation(timestamp, bbbTsp));
				}
			}
			
		}

		/*
		 * 6) Past signature validation: the long term validation process shall perform the past signature validation
		 * process with the following inputs: the signature, the status indication/sub-indication returned in step 2,
		 * the signing certificate, the X.509 validation parameters, certificate validation data, chain constraints,
		 * cryptographic constraints and the set of POEs. If it returns PASSED the long term validation process shall go
		 * to the next step. Otherwise, the long term validation process shall return the indication/sub-indication and
		 * associated explanations returned from the past signature validation process.
		 */
		item = item.setNextItem(pastSignatureValidation(currentContext));
		
		/*
		 * 7) The SVA shall determine from the set of POEs the earliest time the existence of the signature can be proved
		 */
		POE bestSignatureTime = poe.getLowestPOE(signature.getId());
		result.setProofOfExistence(toXmlProofOfExistence(bestSignatureTime));
		
		/*
		 * 8) The SVA shall perform the Signature Acceptance Validation process as per clause 5.2.8 with the following
		 * inputs:
		 * a) The Signed Data Object(s).
		 * b) The time determined in step 7 as the validation time parameter.
		 * c) The Cryptographic Constraints.
		 * NOTE 6: This check has been performed already in step 3 as part of basic signature validation for current time but
		 * is repeated here for the earliest time the signature is known to have existed to e.g. check if the algorithms
		 * were reliable at that time. Signature elements constraints have already been dealt with in step 2 and need
		 * not be rechecked.
		 * If the signature acceptance validation process returns PASSED, the SVA shall go to the next step. 
		 */
		item = item.setNextItem(signatureIsAcceptable(bestSignatureTime.getTime(), currentContext));

		/*
		 * 9) Data extraction: the SVA shall return the success indication PASSED. In addition, the long term validation
		 * process should return additional information extracted from the signature and/or used by the intermediate
		 * steps. In particular, the long term validation process should return intermediate results such as the
		 * validation results of any time-stamp token.
		 * NOTE 7: What the DA does with this information is out of the scope of the present document.
		 */
		
		/*
		 * Otherwise,
		 * the SVA shall return the indication and sub-indication returned by the Signature Acceptance Validation Process
		 */

	}

	private XmlProofOfExistence toXmlProofOfExistence(POE poe) {
		XmlProofOfExistence xmlPoe = new XmlProofOfExistence();
		xmlPoe.setTime(poe.getTime());
		xmlPoe.setTimestampId(poe.getTimestampId());
		return xmlPoe;
	}

	private POE toPOE(XmlProofOfExistence xmlProofOfExistence) {
		String timestampId = xmlProofOfExistence.getTimestampId();
		if (timestampId != null) {
			for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
				if (timestampId.equals(timestamp.getId())) {
					return new POE(timestamp);
				}
			}
		}
		return new POE(xmlProofOfExistence.getTime());
	}
	
	private ChainItem<XmlValidationProcessArchivalData> pastTimestampValidation(TimestampWrapper timestamp, XmlBasicBuildingBlocks bbbTsp) {
		return new PastTimestampValidation(i18nProvider, result, bbbTsp.getPSV(), bbbTsp.getSAV(), timestamp, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationProcessArchivalData> pastSignatureValidation(Context currentContext) {
		return new PastSignatureValidationCheck(i18nProvider, result, signature, bbbs, poe, currentTime, policy,
				currentContext, getFailLevelConstraint());
	}

	private XmlConstraintsConclusion getTimestampValidation(TimestampWrapper newestTimestamp) {
		for (XmlTimestamp xmlTimestamp : xmlTimestamps) {
			if (Utils.areStringsEqual(xmlTimestamp.getId(), newestTimestamp.getId())) {
				return xmlTimestamp.getValidationProcessTimestamp();
			}
		}
		return null;
	}
	
	private MessageImprintDigestAlgorithmValidation timestampDigestAlgorithmValidation(TimestampWrapper newestTimestamp) {
		CryptographicConstraint cryptographicConstraint = policy.getSignatureCryptographicConstraint(Context.TIMESTAMP);
		return new MessageImprintDigestAlgorithmValidation(i18nProvider, newestTimestamp.getProductionTime(),
				newestTimestamp.getMessageImprint().getDigestMethod(), cryptographicConstraint);
	}

	private ChainItem<XmlValidationProcessArchivalData> longTermValidation() {
		return new LongTermValidationCheck(i18nProvider, result, validationProcessLongTermData, getFailLevelConstraint());
	}

	private boolean shouldPerformPastSignatureValidationProcess(XmlConclusion conclusion) {
		return Indication.INDETERMINATE.equals(conclusion.getIndication())
				&& (SubIndication.REVOKED_NO_POE.equals(conclusion.getSubIndication()) || SubIndication.REVOKED_CA_NO_POE.equals(conclusion.getSubIndication())
						|| SubIndication.OUT_OF_BOUNDS_NO_POE.equals(conclusion.getSubIndication())
						|| SubIndication.OUT_OF_BOUNDS_NOT_REVOKED.equals(conclusion.getSubIndication())
						|| SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(conclusion.getSubIndication()));
	}
	
	private ChainItem<XmlValidationProcessArchivalData> signatureIsAcceptable(Date bestSignatureTime, Context context) {
		SignatureAcceptanceValidation sav = new SignatureAcceptanceValidation(i18nProvider, diagnosticData, bestSignatureTime, signature, context, policy);
		XmlSAV savResult = sav.execute();
		return new SignatureAcceptanceValidationResultCheck<>(i18nProvider, result, savResult, getFailLevelConstraint());
	}

}
