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

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.SubContext;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.sav.SignatureAcceptanceValidation;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.DigestMatcherCryptographicCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.SignatureAcceptanceValidationResultCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.SigningCertificateDigestAlgorithmCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.crs.CertificateRevocationSelector;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.RevocationFreshnessChecker;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.RevocationDataAvailableCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateRevocationSelectorResultCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationFreshnessCheckerResultCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.AcceptableBasicSignatureValidationCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.BestSignatureTimeBeforeCertificateExpirationCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.BestSignatureTimeBeforeSuspensionTimeCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.BestSignatureTimeNotBeforeCertificateIssuanceCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.RevocationDateAfterBestSignatureTimeCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.SigningTimeAttributePresentCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.TimestampCoherenceOrderCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.TimestampDelayCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.TimestampMessageImprintCheck;
import eu.europa.esig.dss.validation.process.vpftsp.checks.BasicTimestampValidationCheck;

import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 5.5 Validation process for Signatures with Time and Signatures with Long-Term Validation Data
 */
public class ValidationProcessForSignaturesWithLongTermValidationData extends Chain<XmlValidationProcessLongTermData> {

	/** Basic signature validation conclusion */
	private final XmlConstraintsConclusion basicSignatureValidation;

	/** Diagnostic Data */
	private final DiagnosticData diagnosticData;

	/** The signature */
	private final SignatureWrapper currentSignature;

	/** Map of BasicBuildingBlocks */
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	/** List of timestamps */
	private final List<XmlTimestamp> xmlTimestamps;

	/** Validation policy */
	private final ValidationPolicy policy;

	/** Validation time */
	private final Date currentDate;

	/** Defines the map between certificates in the chain and their latest valid revocation data */
	private Map<CertificateWrapper, CertificateRevocationWrapper> certificateRevocationMap;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param signatureAnalysis {@link XmlSignature}
	 * @param diagnosticData {@link DiagnosticData}
	 * @param currentSignature {@link SignatureWrapper}
	 * @param bbbs map of BasicBuildingBlocks
	 * @param policy {@link ValidationPolicy}
	 * @param currentDate {@link Date}
	 */
	public ValidationProcessForSignaturesWithLongTermValidationData(I18nProvider i18nProvider,
																	XmlSignature signatureAnalysis,
																	DiagnosticData diagnosticData,
																	SignatureWrapper currentSignature,
																	Map<String, XmlBasicBuildingBlocks> bbbs,
																	ValidationPolicy policy, Date currentDate) {
		super(i18nProvider, new XmlValidationProcessLongTermData());

		this.basicSignatureValidation = signatureAnalysis.getValidationProcessBasicSignature();
		this.xmlTimestamps = signatureAnalysis.getTimestamps();

		this.diagnosticData = diagnosticData;
		this.currentSignature = currentSignature;
		this.bbbs = bbbs;

		this.policy = policy;
		this.currentDate = currentDate;
	}
	
	@Override
	protected MessageTag getTitle() {
		return MessageTag.VPFLTVD;
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
		result.setProofOfExistence(bestSignatureTime);

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

		if (!ValidationProcessUtils.isAllowedBasicSignatureValidation(basicSignatureValidation.getConclusion())) {
			return;
		}
		
		/* Revocation BBBs analysis */
		certificateRevocationMap = new LinkedHashMap<>();
		
		for (CertificateWrapper certificateWrapper : currentSignature.getCertificateChain()) {
			if (certificateWrapper.isTrusted()) {
				break;
			}
			if (!ValidationProcessUtils.isRevocationCheckRequired(certificateWrapper)) {
				continue;
			}

			item = item.setNextItem(revocationDataPresent(certificateWrapper, currentContext, getSubContext(certificateWrapper)));

			if (Utils.isCollectionEmpty(certificateWrapper.getCertificateRevocationData())) {
				continue;
			}

			CertificateRevocationSelector certificateRevocationSelector = new LongTermValidationCertificateRevocationSelector(
					i18nProvider, certificateWrapper, currentDate, diagnosticData, bbbs, currentSignature.getId(), policy);
			XmlCRS xmlCRS = certificateRevocationSelector.execute();
			result.getCRS().add(xmlCRS);

			item = item.setNextItem(checkCertificateRevocationSelectorResult(xmlCRS, currentContext, getSubContext(certificateWrapper)));

			CertificateRevocationWrapper latestCertificateRevocation = certificateRevocationSelector.getLatestAcceptableCertificateRevocation();
			
			if (latestCertificateRevocation != null) {
				certificateRevocationMap.put(certificateWrapper, latestCertificateRevocation);
			}
		}
		
		List<TimestampWrapper> filteredTimestamps = new ArrayList<>();

		/*
		 * 3) Signature time-stamp validation:
		 */
		List<TimestampWrapper> signatureTimestamps = currentSignature.getTLevelTimestamps();

		if (Utils.isCollectionNotEmpty(signatureTimestamps)) {

			/*
			 * a) For each time-stamp token in the set of signature time-stamp tokens, the process shall check that the
			 * message imprint has been generated according to the corresponding signature format specification
			 * verification. If the verification fails, the process shall remove the token from the set.
			 */
			for (TimestampWrapper timestampWrapper : signatureTimestamps) {

				item = item.setNextItem(timestampMessageImprint(timestampWrapper));

				if (timestampWrapper.isMessageImprintDataFound() && timestampWrapper.isMessageImprintDataIntact()) {

					/*
					 * b) Time-stamp token validation: For each time-stamp token remaining in the set of signature
					 * time-stamp tokens, the process shall perform the time-stamp validation process as per clause 5.4:
					 *
					 * If PASSED is returned and if the returned generation time is before best-signature-time,
					 * the process shall set best-signature-time to this date and shall try the next token.
					 */
					XmlValidationProcessTimestamp timestampValidationProcess = getTimestampValidationProcess(timestampWrapper.getId());
					if (timestampValidationProcess != null) {
						item = item.setNextItem(timestampBasicSignatureValidation(timestampWrapper, timestampValidationProcess));
					}

					if (isValid(timestampValidationProcess)) {

						filteredTimestamps.add(timestampWrapper);

						Date productionTime = timestampWrapper.getProductionTime();
						if (productionTime.before(bestSignatureTime.getTime())) {
							bestSignatureTime = getProofOfExistence(timestampWrapper);
						}

					}

				}

			}

		}

		/*
		 * 4) Comparing times:
		 * a) If step 2) returned the indication INDETERMINATE with the sub-indication REVOKED_NO_POE or REVOKED_CA_NO_POE:
		 * If the returned revocation time is posterior to best-signature-time, the process shall perform step 4-e).
		 * Otherwise, the process shall return the indication INDETERMINATE with the sub-indication REVOKED_NO_POE or 
		 * REVOKED_CA_NO_POE, respectively.
		 */
		XmlConclusion bsConclusion = basicSignatureValidation.getConclusion();
		if (Indication.INDETERMINATE.equals(bsConclusion.getIndication()) &&
				(SubIndication.REVOKED_NO_POE.equals(bsConclusion.getSubIndication()) || SubIndication.REVOKED_CA_NO_POE.equals(bsConclusion.getSubIndication()))) {
			item = revocationDateAfterBestSignatureTimeValidation(item, bestSignatureTime.getTime(), bsConclusion.getSubIndication());
		}

		/*
		 * b) If step 2) returned the indication PASSED or the indication INDETERMINATE with the sub-indication
		 * OUT_OF_BOUNDS_NO_POE: If best-signature-time is before the issuance date of the signing
		 * certificate, the process shall return the indication FAILED with the sub-indication NOT_YET_VALID.
		 * Otherwise, the process shall return the indication and sub-indication which was returned by step 2).
		 */
		if (Indication.PASSED.equals(bsConclusion.getIndication()) ||
				(Indication.INDETERMINATE.equals(bsConclusion.getIndication()) && SubIndication.OUT_OF_BOUNDS_NO_POE.equals(bsConclusion.getSubIndication()))) {
			// verify signing certificate presence for the check
			if (currentSignature.getSigningCertificate() != null) {
				item = item.setNextItem(bestSignatureTimeNotBeforeCertificateIssuance(
						bestSignatureTime.getTime(), bsConclusion.getIndication(), bsConclusion.getSubIndication()));
			}
		}

		/*
		 * c) If step 2) returned INDETERMINATE with the sub-indication CRYPTO_CONSTRAINTS_FAILURE_NO_POE and the
		 * material concerned by this failure is the signature value or a signed attribute: If the algorithm(s)
		 * concerned were still considered reliable at best-signature-time, the process shall continue with step 4-e).
		 * Otherwise, the process shall return the indication INDETERMINATE with the sub-indication
		 * CRYPTO_CONSTRAINTS_FAILURE_NO_POE.
		 */
		if (isCryptoConstraintFailureNoPoe(bsConclusion)) {
			
			CryptographicConstraint signatureConstraint = policy.getSignatureCryptographicConstraint(currentContext);
			
			// check validity of Cryptographic Constraints for the Signature
			item = item.setNextItem(tokenUsedAlgorithmsAreSecureAtPoeTime(currentSignature, bestSignatureTime.getTime(), 
					ValidationProcessUtils.getCryptoPosition(currentContext), signatureConstraint));
			
			for (XmlDigestMatcher digestMatcher : currentSignature.getDigestMatchers()) {
				item = item.setNextItem(digestMatcherIsSecureAtPoeTime(digestMatcher, bestSignatureTime.getTime(), signatureConstraint));
			}

			for (CertificateRefWrapper certificateRef : currentSignature.getSigningCertificateReferences()) {
				item = item.setNextItem(signCertRefIsSecureAtPoeTime(certificateRef, bestSignatureTime.getTime(), currentContext));
			}

			// check validity of Cryptographic Constraints for the Signing Certificate and CA Certificates
			item = certificateChainReliableAtBestSignatureTime(item, getCurrentTime().getTime(), currentContext);
			
			// check validity of revocation data
			item = revocationDataReliableAtBestSignatureTime(item, getCurrentTime().getTime());
			
		}

		/*
		 * d) If step 2) returned the indication INDETERMINATE with the sub-indication OUT_OF_BOUNDS_NOT_REVOKED: If
		 * best-signature-time is before the issuance date of the signing certificate, the process shall return the indication
		 * FAILED with the sub-indication NOT_YET_VALID. If best-signature-time is before the expiration date of the signing
		 * certificate, the process shall perform step 4-e). Otherwise, the process shall return the indication
		 * INDETERMINATE/OUT_OF_BOUNDS_NOT_REVOKED
		 */
		if (Indication.INDETERMINATE.equals(bsConclusion.getIndication()) && SubIndication.OUT_OF_BOUNDS_NOT_REVOKED.equals(bsConclusion.getSubIndication())) {
			
			item = item.setNextItem(bestSignatureTimeNotBeforeCertificateIssuance(bestSignatureTime.getTime()));
			
			item = item.setNextItem(bestSignatureTimeBeforeCertificateExpiration(bestSignatureTime.getTime()));
			
		}

		if (Utils.isCollectionNotEmpty(filteredTimestamps)) {
			/*
			 * e) For each time-stamp token remaining in the set of signature time-stamp tokens, the process shall check
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
			
			if (!signatureTimestamps.isEmpty() && policy.getTimestampDelayConstraint() != null) {
				/*
				 * a) If no signing-time property/attribute is present, the process shall return the indication
				 * INDETERMINATE with the sub-indication SIG_CONSTRAINTS_FAILURE.
				 */
				item = item.setNextItem(signingTimeAttributePresent(currentContext));
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
		 * 6) If step 2) returned the indication INDETERMINATE with the sub indication
		 * TRY_LATER because the revocation information was not fresh enough: the building block
		 * shall run the Revocation Freshness Checker (clause 5.2.5) with the revocation status
		 * information returned in step 2), the certificate for which the revocation status
		 * is being checked and best signature time. If the checker returns PASSED, the building block
		 * shall go to the next step. Otherwise, the building block shall return the indication INDETERMINATE,
		 * the sub indication TRY_LATER and, if returned from the Revocation Freshness Checker,
		 * the suggestion for when to try the validation again.
		 *
		 * 7) If step 2) returned the indication INDETERMINATE with the sub indication TRY_LATER
		 * because the certificate has been found to be suspended:
		 *    a. If best-signature-time is before the time of suspension of the certificate:
		 *       the process shall go to the step 8).
		 *    b. Otherwise, the building block shall return the indication INDETERMINATE,
		 *       the sub indication TRY_LATER and a suggestion on when to try the validation gain,
		 *       if returned by the validation process in step 2).
		 */
		if (Indication.INDETERMINATE.equals(bsConclusion.getIndication())
				&& SubIndication.TRY_LATER.equals(bsConclusion.getSubIndication())) {
			item = revocationIsFresh(item, bestSignatureTime.getTime(), currentContext);
		}
		
		/*
		 * 8) The SVA shall perform the Signature Acceptance Validation process as per clause 5.2.8 with the following
		 * inputs:
		 * a) The Signed Data Object(s).
		 * b) best-signature-time as the validation time parameter.
		 * c) The Cryptographic Constraints.
		 */
		
		/*
		 * 9) If the signature acceptance validation process returns PASSED, the SVA shall go to the next step.
		 * Otherwise, the SVA shall return the indication and sub-indication returned by
		 * the Signature Acceptance Validation Process.
		 */
		item = item.setNextItem(signatureIsAcceptable(bestSignatureTime.getTime(), currentContext));
		
		/*
		 * 10) Data extraction: the process shall return the success indication PASSED,
		 * the certificate chain obtained in step 2 and best-signature-time.
		 * In addition, the process should return additional information extracted from the signature and/or
		 * used by the intermediate steps.
		 * In particular, the process should return intermediate results such as the validation results
		 * of any signature time-stamp token.
		 */
		result.setProofOfExistence(bestSignatureTime);
	}

	private ChainItem<XmlValidationProcessLongTermData> isAcceptableBasicSignatureValidation() {
		return new AcceptableBasicSignatureValidationCheck(i18nProvider, result, basicSignatureValidation, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> revocationDataPresent(
			CertificateWrapper certificate, Context context, SubContext subContext) {
		LevelConstraint constraint = policy.getRevocationDataAvailableConstraint(context, subContext);
		return new RevocationDataAvailableCheck<>(i18nProvider, result, certificate, constraint, certificate.getId());
	}

	private ChainItem<XmlValidationProcessLongTermData> checkCertificateRevocationSelectorResult(
			XmlCRS crsResult, Context context, SubContext subContext) {
		LevelConstraint constraint = policy.getAcceptableRevocationDataFoundConstraint(context, subContext);
		return new CertificateRevocationSelectorResultCheck<>(i18nProvider, result, crsResult, constraint);
	}

	private ChainItem<XmlValidationProcessLongTermData> timestampMessageImprint(TimestampWrapper timestampWrapper) {
		return new TimestampMessageImprintCheck<>(i18nProvider, result, timestampWrapper, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> timestampBasicSignatureValidation(
			TimestampWrapper timestampWrapper, XmlValidationProcessTimestamp timestampValidationResult) {
		return new BasicTimestampValidationCheck<>(i18nProvider, result, timestampWrapper,
				timestampValidationResult, getWarnLevelConstraint());
	}
	
	private ChainItem<XmlValidationProcessLongTermData> revocationIsFresh(ChainItem<XmlValidationProcessLongTermData> item, 
			Date bestSignatureTime, Context currentContext) {
		for (Map.Entry<CertificateWrapper, CertificateRevocationWrapper> certRevocEntry : certificateRevocationMap.entrySet()) {
			CertificateWrapper certificate = certRevocEntry.getKey();
			SubContext subContext = getSubContext(certificate);

			CertificateRevocationWrapper revocationData = certRevocEntry.getValue();
			if (RevocationReason.CERTIFICATE_HOLD.equals(revocationData.getReason())) {
				item = item.setNextItem(checkCertificateSuspensionNotBeforeBestSignatureTime(revocationData,
						bestSignatureTime, currentContext, subContext));

			} else {
				RevocationFreshnessChecker rfc = new RevocationFreshnessChecker(i18nProvider, revocationData,
						bestSignatureTime, currentContext, subContext, policy);
				XmlRFC xmlRFC = rfc.execute();
				result.getRFC().add(xmlRFC);

				item = item.setNextItem(checkRevocationFreshnessCheckerResult(xmlRFC));

				if (!isValid(xmlRFC)) {
					break;
				}
			}

		}
		return item;
	}

	private ChainItem<XmlValidationProcessLongTermData> checkRevocationFreshnessCheckerResult(XmlRFC rfcResult) {
		return new RevocationFreshnessCheckerResultCheck<XmlValidationProcessLongTermData>(i18nProvider, result, rfcResult, getFailLevelConstraint()) {
			@Override
			protected Indication getFailedIndicationForConclusion() {
				return Indication.INDETERMINATE;
			}

			@Override
			protected SubIndication getFailedSubIndicationForConclusion() {
				return SubIndication.TRY_LATER;
			}
		};
	}

	private ChainItem<XmlValidationProcessLongTermData> checkCertificateSuspensionNotBeforeBestSignatureTime(
			CertificateRevocationWrapper certificateRevocationWrapper, Date bestSignatureTime,
			Context context, SubContext subContext) {
		LevelConstraint constraint = policy.getCertificateNotOnHoldConstraint(context, subContext);
		return new BestSignatureTimeBeforeSuspensionTimeCheck(
				i18nProvider, result, certificateRevocationWrapper, bestSignatureTime, constraint);
	}

	private ChainItem<XmlValidationProcessLongTermData> revocationDateAfterBestSignatureTimeValidation(
			ChainItem<XmlValidationProcessLongTermData> item, Date bestSignatureTime, SubIndication subIndication) {
		
		LevelConstraint constraint = policy.getRevocationTimeAgainstBestSignatureTimeConstraint();
		
		for (Map.Entry<CertificateWrapper, CertificateRevocationWrapper> certRevMapEntry : certificateRevocationMap.entrySet()) {
			CertificateWrapper certificate = certRevMapEntry.getKey();
			CertificateRevocationWrapper revocationData = certRevMapEntry.getValue();
			SubContext subContext = getSubContext(certificate);
			
			// separate cases to check based on the returned subIndication
			if ((SubContext.SIGNING_CERT.equals(subContext) && SubIndication.REVOKED_NO_POE.equals(subIndication)) ||
					SubContext.CA_CERTIFICATE.equals(subContext) && SubIndication.REVOKED_CA_NO_POE.equals(subIndication)) {
				item = item.setNextItem(new RevocationDateAfterBestSignatureTimeCheck(i18nProvider, result, revocationData, 
						bestSignatureTime, constraint, subContext));
			}
		}
		
		return item;
	}

	private ChainItem<XmlValidationProcessLongTermData> bestSignatureTimeNotBeforeCertificateIssuance(Date bestSignatureTime,
			Indication currentIndication, SubIndication currentSubIndication) {
		CertificateWrapper signingCertificate = currentSignature.getSigningCertificate();
		return new BestSignatureTimeNotBeforeCertificateIssuanceCheck<>(i18nProvider, result,
				bestSignatureTime, signingCertificate, currentIndication, currentSubIndication, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> bestSignatureTimeNotBeforeCertificateIssuance(Date bestSignatureTime) {
		CertificateWrapper signingCertificate = currentSignature.getSigningCertificate();
		return new BestSignatureTimeNotBeforeCertificateIssuanceCheck<>(i18nProvider, result,
				bestSignatureTime, signingCertificate, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> bestSignatureTimeBeforeCertificateExpiration(Date bestSignatureTime) {
		CertificateWrapper signingCertificate = currentSignature.getSigningCertificate();
		return new BestSignatureTimeBeforeCertificateExpirationCheck(i18nProvider, result, bestSignatureTime, signingCertificate,
				policy.getBestSignatureTimeBeforeExpirationDateOfSigningCertificateConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> timestampCoherenceOrder(List<TimestampWrapper> timestamps) {
		return new TimestampCoherenceOrderCheck(i18nProvider, result, timestamps, policy.getTimestampCoherenceConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> signingTimeAttributePresent(Context context) {
		return new SigningTimeAttributePresentCheck(i18nProvider, result, currentSignature, policy.getSigningTimeConstraint(context));
	}

	private ChainItem<XmlValidationProcessLongTermData> timestampDelay(Date bestSignatureTime) {
		return new TimestampDelayCheck(i18nProvider, result, currentSignature, bestSignatureTime, policy.getTimestampDelayConstraint());
	}

	private ChainItem<XmlValidationProcessLongTermData> tokenUsedAlgorithmsAreSecureAtPoeTime(TokenProxy currentToken, Date validationDate, 
			MessageTag position, CryptographicConstraint constraint) {
		return new CryptographicCheck<>(i18nProvider, result, currentToken,  position, validationDate, constraint);
	}
	
	private ChainItem<XmlValidationProcessLongTermData> digestMatcherIsSecureAtPoeTime(XmlDigestMatcher digestMatcher, Date validationDate, 
			CryptographicConstraint constraint) {
		MessageTag position = ValidationProcessUtils.getDigestMatcherCryptoPosition(digestMatcher);
		return new DigestMatcherCryptographicCheck<>(i18nProvider, digestMatcher.getDigestMethod(), result, validationDate, position, constraint);
	}

	private ChainItem<XmlValidationProcessLongTermData> signCertRefIsSecureAtPoeTime(
			CertificateRefWrapper signCertReference, Date validationDate, Context context) {
		SubContext subContext;
		if (currentSignature.getSigningCertificate() != null &&
				currentSignature.getSigningCertificate().getId().equals(signCertReference.getCertificateId())) {
			subContext = SubContext.SIGNING_CERT;
		} else {
			subContext = SubContext.CA_CERTIFICATE;
		}

		CryptographicConstraint cryptographicConstraint = policy.getCertificateCryptographicConstraint(context, subContext);

		LevelConstraint constraint = policy.getSigningCertificateDigestAlgorithmConstraint(context);
		return new SigningCertificateDigestAlgorithmCheck<>(i18nProvider, signCertReference, result, validationDate,
				cryptographicConstraint, constraint);
	}
	
	private ChainItem<XmlValidationProcessLongTermData> signatureIsAcceptable(Date bestSignatureTime, Context context) {
		SignatureAcceptanceValidation sav = new SignatureAcceptanceValidation(i18nProvider, diagnosticData, bestSignatureTime, currentSignature, context, policy);
		return new SignatureAcceptanceValidationResultCheck<>(i18nProvider, result, sav.execute(), getFailLevelConstraint());
	}
	
	/**
	 * Set up cryptographic check for certificates used in the certificate chain of the signature
	 * @param item - the last {@link ChainItem}
	 * @param bestSignatureTime - {@link Date} to check cryptographic constraints validity
	 * @return last established {@link ChainItem}
	 */
	private ChainItem<XmlValidationProcessLongTermData> certificateChainReliableAtBestSignatureTime(ChainItem<XmlValidationProcessLongTermData> item, 
			Date bestSignatureTime, Context context) {
		for (CertificateWrapper certificate : currentSignature.getCertificateChain()) {
			if (certificate.isTrusted()) {
				break;
			}
			SubContext subContext = currentSignature.getSigningCertificate().getId().equals(certificate.getId()) ? SubContext.SIGNING_CERT : SubContext.CA_CERTIFICATE;
			item = item.setNextItem(tokenUsedAlgorithmsAreSecureAtPoeTime(certificate, bestSignatureTime, 
					ValidationProcessUtils.getCertificateChainCryptoPosition(context), policy.getCertificateCryptographicConstraint(context, subContext)));
		}
		
		return item;
	}

	private ChainItem<XmlValidationProcessLongTermData> revocationDataReliableAtBestSignatureTime(
			ChainItem<XmlValidationProcessLongTermData> item, Date bestSignatureTime) {
		List<String> checkedTokenIds = new ArrayList<>();
		for (CertificateRevocationWrapper revocationData : certificateRevocationMap.values()) {
			item = checkRevocationAgainstBestSignatureTime(item, revocationData, bestSignatureTime, checkedTokenIds);
		}
		return item;
	}
	
	private ChainItem<XmlValidationProcessLongTermData> checkRevocationAgainstBestSignatureTime(
			ChainItem<XmlValidationProcessLongTermData> item, RevocationWrapper revocationData, Date bestSignatureTime, List<String> checkedTokenIds) {
		XmlBasicBuildingBlocks revocationBBB = bbbs.get(revocationData.getId());
		if (!checkedTokenIds.contains(revocationData.getId()) && 
				revocationBBB != null && isCryptoConstraintFailureNoPoe(revocationBBB.getConclusion())) {
			
			item = item.setNextItem(tokenUsedAlgorithmsAreSecureAtPoeTime(revocationData, bestSignatureTime, 
					ValidationProcessUtils.getCryptoPosition(Context.REVOCATION), policy.getSignatureCryptographicConstraint(Context.REVOCATION)));
			
			checkedTokenIds.add(revocationData.getId());
			
			XmlXCV xcv = revocationBBB.getXCV();
			if (xcv != null && isCryptoConstraintFailureNoPoe(xcv.getConclusion())) {
				for (XmlSubXCV subXCV : xcv.getSubXCV()) {
					if (!checkedTokenIds.contains(subXCV.getId()) && isCryptoConstraintFailureNoPoe(subXCV.getConclusion())) {
						CertificateWrapper certificateWrapper = diagnosticData.getUsedCertificateById(subXCV.getId());
						SubContext subContext = revocationData.getSigningCertificate().getId().equals(certificateWrapper.getId()) ?
								SubContext.SIGNING_CERT : SubContext.CA_CERTIFICATE;
						
						item = item.setNextItem(tokenUsedAlgorithmsAreSecureAtPoeTime(certificateWrapper, bestSignatureTime, 
								ValidationProcessUtils.getCertificateChainCryptoPosition(Context.REVOCATION), 
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

	private SubContext getSubContext(CertificateWrapper certificateWrapper) {
		return currentSignature.getSigningCertificate().getId().equals(certificateWrapper.getId()) ?
				SubContext.SIGNING_CERT : SubContext.CA_CERTIFICATE;
	}

	private XmlProofOfExistence getCurrentTime() {
		XmlProofOfExistence poe = new XmlProofOfExistence();
		poe.setTime(currentDate);
		return poe;
	}

	private XmlProofOfExistence getProofOfExistence(TimestampWrapper timestampWrapper) {
		XmlProofOfExistence xpoe = new XmlProofOfExistence();
		xpoe.setTime(timestampWrapper.getProductionTime());
		xpoe.setTimestampId(timestampWrapper.getId());
		return xpoe;
	}
	
	private XmlValidationProcessTimestamp getTimestampValidationProcess(String timestampId) {
		for (XmlTimestamp xmlTimestamp : xmlTimestamps) {
			if (timestampId.equals(xmlTimestamp.getId())) {
				return xmlTimestamp.getValidationProcessTimestamp();
			}
		}
		return null;
	}
	
	private boolean isCryptoConstraintFailureNoPoe(XmlConclusion conclusion) {
		return Indication.INDETERMINATE.equals(conclusion.getIndication()) && 
				SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(conclusion.getSubIndication());
	}
	
	@Override
	protected void collectMessages(XmlConclusion conclusion, XmlConstraint constraint) {
		if (XmlBlockType.TST_BBB.equals(constraint.getBlockType())) {
			// skip validation for TSTs
		} else {
			super.collectMessages(conclusion, constraint);
		}
	}

	@Override
	protected void collectAdditionalMessages(XmlConclusion conclusion) {
		if (!ValidationProcessUtils.isAllowedBasicSignatureValidation(basicSignatureValidation.getConclusion())) {
			conclusion.getWarnings().addAll(basicSignatureValidation.getConclusion().getWarnings());
			conclusion.getInfos().addAll(basicSignatureValidation.getConclusion().getInfos());
		}
	}

}
