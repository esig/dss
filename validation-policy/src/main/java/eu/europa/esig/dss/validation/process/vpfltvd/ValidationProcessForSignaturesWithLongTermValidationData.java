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
package eu.europa.esig.dss.validation.process.vpfltvd;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.SubContext;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessDefinition;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.sav.SignatureAcceptanceValidation;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.SignatureAcceptanceValidationResultCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationConsistentCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.RevocationFreshnessChecker;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.AcceptableRevocationDataAvailableCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationFreshnessCheckerResultCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.AcceptableBasicSignatureValidationCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.BestSignatureTimeNotBeforeCertificateIssuanceCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.RevocationBasicBuildingBlocksCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.RevocationDateAfterBestSignatureTimeCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.SigningTimeAttributePresentCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.TimestampCoherenceOrderCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.TimestampDelayCheck;

/**
 * 5.5 Validation process for Signatures with Time and Signatures with Long-Term Validation Data
 */
public class ValidationProcessForSignaturesWithLongTermValidationData extends Chain<XmlValidationProcessLongTermData> {

	private static final Logger LOG = LoggerFactory.getLogger(ValidationProcessForSignaturesWithLongTermValidationData.class);

	private final XmlConstraintsConclusion basicSignatureValidation;

	private final DiagnosticData diagnosticData;
	private final SignatureWrapper currentSignature;
	private final Map<String, XmlBasicBuildingBlocks> bbbs;
	private final List<XmlTimestamp> xmlTimestamps;

	private final ValidationPolicy policy;
	private final Date currentDate;

	public ValidationProcessForSignaturesWithLongTermValidationData(I18nProvider i18nProvider, XmlSignature signatureAnalysis, DiagnosticData diagnosticData,
			SignatureWrapper currentSignature, Map<String, XmlBasicBuildingBlocks> bbbs, ValidationPolicy policy, Date currentDate) {
		super(i18nProvider, new XmlValidationProcessLongTermData());
		result.setTitle(ValidationProcessDefinition.VPFLTVD.getTitle());

		this.basicSignatureValidation = signatureAnalysis.getValidationProcessBasicSignature();
		this.xmlTimestamps = signatureAnalysis.getTimestamp();

		this.diagnosticData = diagnosticData;
		this.currentSignature = currentSignature;
		this.bbbs = bbbs;

		this.policy = policy;
		this.currentDate = currentDate;
	}

	@Override
	protected void initChain() {

		Context currentContext = Context.SIGNATURE;
		if (currentSignature.isCounterSignature()) {
			currentContext = Context.COUNTER_SIGNATURE;
		}

		/*
		 * 5.5.4 1) The process shall initialize the set of signature time-stamp tokens from the signature time-stamp
		 * attributes present in the signature and shall initialize the best-signature-time to the current time.
		 * NOTE 1: Best-signature-time is an internal variable for the algorithm denoting the earliest time when it can
		 * be proven that a signature has existed.
		 */
		XmlProofOfExistence bestSignatureTime = getCurrentTime();

		/*
		 * 2) Signature validation: the process shall perform the validation process for Basic Signatures as per
		 * clause 5.3 with all the inputs, including the processing of any signed attributes as specified. If the
		 * Signature contains long-term validation data, this data shall be passed to the validation process for Basic
		 * Signatures.
		 * 
		 * If this validation returns PASSED, INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE,
		 * INDETERMINATE/REVOKED_NO_POE, INDETERMINATE/REVOKED_CA_NO_POE,
		 * INDETERMINATE/TRY_LATER or INDETERMINATE/OUT_OF_BOUNDS_NO_POE, the SVA shall go
		 * to the next step. Otherwise, the process shall return the status and information returned by the validation
		 * process for Basic Signatures. 
		 */
		ChainItem<XmlValidationProcessLongTermData> item = firstItem = isAcceptableBasicSignatureValidation();
		
		/* RevocatioN BBBs analysis */
		Map<CertificateRevocationWrapper, SubContext> revocationDataToUse = new LinkedHashMap<CertificateRevocationWrapper, SubContext>();
		
		for (CertificateWrapper certificateWrapper : currentSignature.getCertificateChain()) {
			if (certificateWrapper.isTrusted()) {
				break;
			}
			CertificateRevocationWrapper latestCertificateRevocation = null;
			for (CertificateRevocationWrapper revocationData : certificateWrapper.getCertificateRevocationData()) {
				XmlBasicBuildingBlocks revocationBBB = bbbs.get(revocationData.getId());
				
				item = item.setNextItem(revocationBasicBuildingBlocksValid(revocationBBB));
				
				if (ValidationProcessUtils.isAllowedBasicSignatureValidation(revocationBBB.getConclusion())) {
					
					item = item.setNextItem(revocationDataConsistent(certificateWrapper, revocationData));
					
					if (isRevocationDataConsistent(certificateWrapper, revocationData) && 
							(latestCertificateRevocation == null || revocationData.getProductionDate().after(latestCertificateRevocation.getProductionDate()))) {
						latestCertificateRevocation = revocationData;
					}
				}
			}
			
			SubContext subContext = currentSignature.getSigningCertificate().getId().equals(certificateWrapper.getId()) ? 
					SubContext.SIGNING_CERT : SubContext.CA_CERTIFICATE;
			
			item = item.setNextItem(revocationDataAvailable(latestCertificateRevocation, certificateWrapper, currentContext, subContext));
			
			if (latestCertificateRevocation != null) {
				revocationDataToUse.put(latestCertificateRevocation, subContext);
			}
		}
		

		/*
		 * 3) Signature time-stamp validation:
		 * a) For each time-stamp token in the set of signature time-stamp tokens, the process shall check that the
		 * message imprint has been generated according to the corresponding signature format specification
		 * verification. If the verification fails, the process shall remove the token from the set.
		 */
		Set<TimestampWrapper> allowedTimestamps = filterValidSignatureTimestamps(currentSignature.getTimestampList());

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
				if (isAcceptableTimestampValidation(timestampWrapper) && productionTime.before(bestSignatureTime.getTime())) {
					bestSignatureTime = getProofOfExistence(timestampWrapper);
				}
			}
		}

		/*
		 * 4) Comparing times:
		 * a) If step 2 returned the indication INDETERMINATE with the sub-indication REVOKED_NO_POE or REVOKED_CA_NO_POE:
		 * If the returned revocation time is posterior to best-signature-time, the process shall perform step 4d.
		 * Otherwise, the process shall return the indication INDETERMINATE with the sub-indication REVOKED_NO_POE or REVOKED_CA_NO_POE respectively.
		 */
		XmlConclusion bsConclusion = basicSignatureValidation.getConclusion();
		if (Indication.INDETERMINATE.equals(bsConclusion.getIndication()) && 
				(SubIndication.REVOKED_NO_POE.equals(bsConclusion.getSubIndication()) || SubIndication.REVOKED_CA_NO_POE.equals(bsConclusion.getSubIndication()))) {
			item = revocationDateAfterBestSignatureDateValidation(item, revocationDataToUse, bestSignatureTime.getTime(), bsConclusion.getSubIndication());
		}

		/*
		 * b) If step 2 returned the indication INDETERMINATE with the sub-indication
		 * OUT_OF_BOUNDS_NO_POE: If best-signature-time is before the issuance date of the signing
		 * certificate, the process shall return the indication FAILED with the sub-indication NOT_YET_VALID.
		 * Otherwise, the process shall return the indication INDETERMINATE with the sub-indication
		 * OUT_OF_BOUNDS_NO_POE.
		 */
		if (Indication.INDETERMINATE.equals(bsConclusion.getIndication()) && SubIndication.OUT_OF_BOUNDS_NO_POE.equals(bsConclusion.getSubIndication())) {
			item = item.setNextItem(bestSignatureTimeNotBeforeCertificateIssuance(bestSignatureTime.getTime()));
		}

		/*
		 * c) If step 2 returned INDETERMINATE with the sub-indication CRYPTO_CONSTRAINTS_FAILURE_NO_POE and the
		 * material concerned by this failure is the signature value or a signed attribute: If the algorithm(s)
		 * concerned were still considered reliable at best-signature-time, the process shall continue with step d.
		 * Otherwise, the process shall return the indication INDETERMINATE with the sub-indication
		 * CRYPTO_CONSTRAINTS_FAILURE_NO_POE.
		 */
		if (isCryptoConstraintFailureNoPoe(bsConclusion)) {
			
			// check validity of Cryptographic Constraints for the Signature
			item = item.setNextItem(algorithmReliableAtBestSignatureTime(bestSignatureTime.getTime()));

			// check validity of Cryptographic Constraints for the Signing Certificate and CA Certificates
			item = certificateChainReliableAtBestSignatureTime(item, bestSignatureTime.getTime());
			
			// check validity of revocation data
			item = revocationDataReliableAtBestSignatureTime(item, revocationDataToUse, bestSignatureTime.getTime());
			
		}

		if (Utils.isCollectionNotEmpty(allowedTimestamps)) {
			/*
			 * d) For each time-stamp token remaining in the set of signature time-stamp tokens, the process shall check
			 * the coherence in the values of the times indicated in the time-stamp tokens. They shall be posterior to
			 * the times indicated in any time-stamp token computed on the signed data (content-time-stamp). The process shall apply the
			 * rules specified in IETF RFC 3161 [3], clause 2.4.2 regarding the order of time-stamp tokens generated by the
			 * same or different TSAs given the accuracy and ordering fields' values of the TSTInfo field,
			 * unless stated differently by the signature validation constraints. If all the checks end successfully,
			 * the process shall go to the next step. Otherwise the process shall return the indication INDETERMINATE with the
			 * sub-indication TIMESTAMP_ORDER_FAILURE.
			 */
			item = item.setNextItem(timestampCoherenceOrder(currentSignature.getTimestampList()));


			/*
			 * 5) Handling Time-stamp delay: If the signature contains a signature time-stamp token and the validation
			 * constraints specify a time-stamp delay:
			 */
			List<TimestampWrapper> signatureTimestamps = currentSignature.getTimestampListByType(TimestampType.SIGNATURE_TIMESTAMP);
			
			if (!signatureTimestamps.isEmpty() && policy.getTimestampDelayConstraint() != null) {
				/*
				 * a) If no signing-time property/attribute is present, the process shall return the indication
				 * INDETERMINATE with the sub-indication SIG_CONSTRAINTS_FAILURE.
				 */
				item = item.setNextItem(signingTimeAttributePresent());
				/*
				 * b) If a signing-time property/attribute is present, the process shall check that the claimed time in the
				 * attribute plus the time-stamp delay is after the best-signature-time. If the check is successful, the
				 * process shall go to the next step. Otherwise, the process shall return the indication INDETERMINATE with the
				 * sub-indication SIG_CONSTRAINTS_FAILURE.
				 */
				item = item.setNextItem(timestampDelay(bestSignatureTime.getTime()));
			}
		}
		
		/*
		 * 6) If step 2 returned the indication INDETERMINATE with the sub-indication TRY_LATER: the building block
		 * shall run the Revocation Freshness Checker (clause 5.2.5) with the revocation status information returned in
		 * step 2, the certificate for which the revocation status is being checked and best-signature-time. If the checker
		 * returns PASSED, the building block shall go to the next step. Otherwise, the building block shall return the
		 * indication INDETERMINATE, the sub-indication TRY_LATER and, if returned from the Revocation Freshness
		 * Checker, the suggestion for when to try the validation again. 
		 */
		if (Indication.INDETERMINATE.equals(bsConclusion.getIndication())
				&& SubIndication.TRY_LATER.equals(bsConclusion.getSubIndication())) {
			item = revocationIsFresh(item, revocationDataToUse, bestSignatureTime.getTime(), currentContext);
		}
		
		/*
		 * 7) The SVA shall perform the Signature Acceptance Validation process as per clause 5.2.8 with the following
		 * inputs:
		 * a) The Signed Data Object(s).
		 * b) best-signature-time as the validation time parameter.
		 * c) The Cryptographic Constraints.
		 */
		
		/*
		 * 8) If the signature acceptance validation process returns PASSED, the SVA shall go to the next step. Otherwise,
		 * the SVA shall return the indication and sub-indication returned by the Signature Acceptance Validation
		 * Process. 
		 */
		item = item.setNextItem(signatureIsAcceptable(bestSignatureTime.getTime(), currentContext));
		
		/*
		 * 9) Data extraction: the process shall return the success indication PASSED, the certificate chain obtained in step 2
		 * and best-signature-time.
		 * In addition, the process should return additional information extracted from the signature and/or used by the
		 * intermediate steps.
		 * In particular, the process should return intermediate results such as the validation results of any signature
		 * time-stamp token. 
		 */

		result.setProofOfExistence(bestSignatureTime);
	}

	private ChainItem<XmlValidationProcessLongTermData> revocationBasicBuildingBlocksValid(XmlBasicBuildingBlocks revocationBBB) {
		return new RevocationBasicBuildingBlocksCheck(i18nProvider, result, revocationBBB, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> revocationDataConsistent(CertificateWrapper certificate, CertificateRevocationWrapper revocationData) {
		return new RevocationConsistentCheck<XmlValidationProcessLongTermData>(i18nProvider, result, certificate, revocationData, getWarnLevelConstraint());
	}
	
	private boolean isRevocationDataConsistent(CertificateWrapper certificate, CertificateRevocationWrapper revocationData) {
		XmlBasicBuildingBlocks signatureBBB = bbbs.get(currentSignature.getId());
		if (signatureBBB.getXCV() != null) {
			for (XmlSubXCV subXCV : signatureBBB.getXCV().getSubXCV()) {
				if (certificate.getId().equals(subXCV.getId()) && 
						subXCV.getRFC() != null && revocationData.getId().equals(subXCV.getRFC().getId())) {
					// RFC is performed only for consistent revocation
					return true;
				}
			}
		}
		return false;
	}

	private ChainItem<XmlValidationProcessLongTermData> revocationDataAvailable(RevocationWrapper revocationData, 
			CertificateWrapper certificateWrapper, Context context, SubContext subContext) {
		LevelConstraint constraint = policy.getRevocationDataAvailableConstraint(context, subContext);
		return new AcceptableRevocationDataAvailableCheck<XmlValidationProcessLongTermData>(i18nProvider, result, certificateWrapper, revocationData, constraint);
	}

	private XmlProofOfExistence getCurrentTime() {
		XmlProofOfExistence xpoe = new XmlProofOfExistence();
		xpoe.setTime(currentDate);
		return xpoe;
	}

	private XmlProofOfExistence getProofOfExistence(TimestampWrapper timestampWrapper) {
		XmlProofOfExistence xpoe = new XmlProofOfExistence();
		xpoe.setTime(timestampWrapper.getProductionTime());
		xpoe.setTimestampId(timestampWrapper.getId());
		return xpoe;
	}

	private Set<TimestampWrapper> filterValidSignatureTimestamps(List<TimestampWrapper> allTimestamps) {
		Set<TimestampWrapper> result = new HashSet<TimestampWrapper>();
		for (TimestampWrapper timestampWrapper : allTimestamps) {
			if (!TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
				break;
			}

			XmlBasicBuildingBlocks bbbTST = bbbs.get(timestampWrapper.getId());
			if (bbbTST != null) {
				// PVA : if OK message imprint is validated in SVA of timestamp (depending of
				// constraint.xml)
				XmlCV cv = bbbTST.getCV();
				if (cv != null) {
					XmlConclusion conclusion = cv.getConclusion();
					if (Indication.PASSED.equals(conclusion.getIndication())) {
						result.add(timestampWrapper);
					}
				} else {
					LOG.warn("Cryptographic validation (CV) for timestamp is required !");
				}
			} else {
				LOG.warn("Cannot find tsp validation info for tsp {}", timestampWrapper.getId());
			}
		}
		return result;
	}
	
	private boolean isAcceptableTimestampValidation(TimestampWrapper timestamp) {
		for (XmlTimestamp xmlTimestamp : xmlTimestamps) {
			if (timestamp.getId().equals(xmlTimestamp.getId()) && isValid(xmlTimestamp.getValidationProcessTimestamp())) {
				return true;
			}
		}
		return false;
	}

	private ChainItem<XmlValidationProcessLongTermData> isAcceptableBasicSignatureValidation() {
		return new AcceptableBasicSignatureValidationCheck(i18nProvider, result, basicSignatureValidation, getFailLevelConstraint());
	}
	
	private ChainItem<XmlValidationProcessLongTermData> revocationIsFresh(ChainItem<XmlValidationProcessLongTermData> item, 
			Map<CertificateRevocationWrapper, SubContext> revocationDataMap, Date bestSignatureTime, Context currentContext) {
		for (Map.Entry<CertificateRevocationWrapper, SubContext> revocationEntry : revocationDataMap.entrySet()) {
			CertificateRevocationWrapper revocationData = revocationEntry.getKey();
			SubContext subContext = revocationEntry.getValue();
			RevocationFreshnessChecker rfc = new RevocationFreshnessChecker(i18nProvider, revocationData, bestSignatureTime, 
					currentContext, subContext, policy);
			item = item.setNextItem(checkRevocationFreshnessCheckerResult(rfc.execute(), currentContext, subContext));
		}
		return item;
	}
	
	
	
	private ChainItem<XmlValidationProcessLongTermData> checkRevocationFreshnessCheckerResult(XmlRFC rfcResult, Context context, SubContext subContext) {
		LevelConstraint constraint = policy.getCertificateRevocationFreshnessConstraint(context, subContext);
		return new RevocationFreshnessCheckerResultCheck<XmlValidationProcessLongTermData>(i18nProvider, result, rfcResult, constraint) {
			@Override
			protected Indication getFailedIndicationForConclusion() { return Indication.INDETERMINATE; }
			@Override
			protected SubIndication getFailedSubIndicationForConclusion() { return SubIndication.TRY_LATER; }
		};
	}

	private ChainItem<XmlValidationProcessLongTermData> revocationDateAfterBestSignatureDateValidation(
			ChainItem<XmlValidationProcessLongTermData> item, Map<CertificateRevocationWrapper, SubContext> revocationDataMap, 
			Date bestSignatureTime, SubIndication subIndication) {
		
		LevelConstraint constraint = policy.getRevocationTimeAgainstBestSignatureTime();
		
		for (Map.Entry<CertificateRevocationWrapper, SubContext> revocationMapEntry : revocationDataMap.entrySet()) {
			CertificateRevocationWrapper revocationData = revocationMapEntry.getKey();
			SubContext subContext = revocationMapEntry.getValue();
			
			// separate cases to check based on the returned subIndication
			if ((SubContext.SIGNING_CERT.equals(subContext) && SubIndication.REVOKED_NO_POE.equals(subIndication)) ||
					SubContext.CA_CERTIFICATE.equals(subContext) && SubIndication.REVOKED_CA_NO_POE.equals(subIndication)) {
				item = item.setNextItem(new RevocationDateAfterBestSignatureTimeCheck(i18nProvider, result, revocationData, 
						bestSignatureTime, constraint, subContext));
			}
		}
		
		return item;
	}

	private ChainItem<XmlValidationProcessLongTermData> bestSignatureTimeNotBeforeCertificateIssuance(Date bestSignatureTime) {
		CertificateWrapper signingCertificate = currentSignature.getSigningCertificate();
		return new BestSignatureTimeNotBeforeCertificateIssuanceCheck(i18nProvider, result, bestSignatureTime, signingCertificate,
				policy.getBestSignatureTimeBeforeIssuanceDateOfSigningCertificateConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> timestampCoherenceOrder(List<TimestampWrapper> timestamps) {
		return new TimestampCoherenceOrderCheck(i18nProvider, result, timestamps, policy.getTimestampCoherenceConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> signingTimeAttributePresent() {
		return new SigningTimeAttributePresentCheck(i18nProvider, result, currentSignature, policy.getSigningTimeConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> timestampDelay(Date bestSignatureTime) {
		return new TimestampDelayCheck(i18nProvider, result, currentSignature, bestSignatureTime, policy.getTimestampDelayConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> algorithmReliableAtBestSignatureTime(Date bestSignatureTime) {
		return new CryptographicCheck<XmlValidationProcessLongTermData>(i18nProvider, result, currentSignature, bestSignatureTime,
				policy.getSignatureCryptographicConstraint(Context.SIGNATURE));
	}
	
	private ChainItem<XmlValidationProcessLongTermData> signatureIsAcceptable(Date bestSignatureTime, Context context) {
		SignatureAcceptanceValidation sav = new SignatureAcceptanceValidation(i18nProvider, diagnosticData, bestSignatureTime, currentSignature, context, policy);
		return new SignatureAcceptanceValidationResultCheck<XmlValidationProcessLongTermData>(i18nProvider, result, sav.execute(), getFailLevelConstraint());
	}
	
	/**
	 * Set up cryptographic check for certificates used in the certificate chain of the signature
	 * @param item - the last {@link ChainItem}
	 * @param bestSignatureTime - {@link Date} to check cryptographic constraints validity
	 * @return last established {@link ChainItem}
	 */
	private ChainItem<XmlValidationProcessLongTermData> certificateChainReliableAtBestSignatureTime(ChainItem<XmlValidationProcessLongTermData> item, Date bestSignatureTime) {
		for (CertificateWrapper certificate : currentSignature.getCertificateChain()) {
			if (certificate.isTrusted()) {
				break;
			}
			SubContext subContext = currentSignature.getSigningCertificate().getId().equals(certificate.getId()) ? SubContext.SIGNING_CERT : SubContext.CA_CERTIFICATE;
			item = item.setNextItem(new CryptographicCheck<XmlValidationProcessLongTermData>(i18nProvider, result, certificate, bestSignatureTime, 
					policy.getCertificateCryptographicConstraint(Context.SIGNATURE, subContext)));
		}
		
		return item;
	}

	private ChainItem<XmlValidationProcessLongTermData> revocationDataReliableAtBestSignatureTime(
			ChainItem<XmlValidationProcessLongTermData> item, Map<CertificateRevocationWrapper, SubContext> revocationDataToUse, Date bestSignatureTime) {
		List<String> checkedTokenIds = new ArrayList<String>();
		for (CertificateRevocationWrapper revocationData : revocationDataToUse.keySet()) {
			item = checkRevocationAgainstBestSignatureTime(item, revocationData, bestSignatureTime, checkedTokenIds);
		}
		return item;
	}
	
	private ChainItem<XmlValidationProcessLongTermData> checkRevocationAgainstBestSignatureTime(
			ChainItem<XmlValidationProcessLongTermData> item, RevocationWrapper revocationData, Date bestSignatureTime, List<String> checkedTokenIds) {
		XmlBasicBuildingBlocks revocationBBB = bbbs.get(revocationData.getId());
		if (!checkedTokenIds.contains(revocationData.getId()) && 
				revocationBBB != null && isCryptoConstraintFailureNoPoe(revocationBBB.getConclusion())) {
			
			item = item.setNextItem(new CryptographicCheck<XmlValidationProcessLongTermData>(i18nProvider, result, revocationData, 
					bestSignatureTime, policy.getSignatureCryptographicConstraint(Context.REVOCATION)));
			
			checkedTokenIds.add(revocationData.getId());
			
			XmlXCV xcv = revocationBBB.getXCV();
			if (xcv != null && isCryptoConstraintFailureNoPoe(xcv.getConclusion())) {
				for (XmlSubXCV subXCV : xcv.getSubXCV()) {
					if (!checkedTokenIds.contains(subXCV.getId()) && isCryptoConstraintFailureNoPoe(subXCV.getConclusion())) {
						CertificateWrapper certificateWrapper = diagnosticData.getUsedCertificateById(subXCV.getId());
						SubContext subContext = revocationData.getSigningCertificate().getId().equals(certificateWrapper.getId()) ?
								SubContext.SIGNING_CERT : SubContext.CA_CERTIFICATE;
						
						item = item.setNextItem(new CryptographicCheck<XmlValidationProcessLongTermData>(i18nProvider, result, certificateWrapper, bestSignatureTime, 
								policy.getCertificateCryptographicConstraint(Context.REVOCATION, subContext)));
						
						if (subXCV.getRFC() != null && isCryptoConstraintFailureNoPoe(subXCV.getRFC().getConclusion())) {
							RevocationWrapper revocationWrapper = diagnosticData.getRevocationById(subXCV.getRFC().getId());
							item = checkRevocationAgainstBestSignatureTime(item, revocationWrapper, bestSignatureTime, checkedTokenIds);
						}
						
					}
				}
			}
		}
		return item;
	}
	
	private boolean isCryptoConstraintFailureNoPoe(XmlConclusion conclusion) {
		return Indication.INDETERMINATE.equals(conclusion.getIndication()) && 
				SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(conclusion.getSubIndication());
	}
	
}
