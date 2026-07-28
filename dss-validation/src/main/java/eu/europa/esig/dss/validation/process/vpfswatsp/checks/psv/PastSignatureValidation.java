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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv;

import eu.europa.esig.dss.detailedreport.jaxb.XmlAOV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRFC;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.SubContext;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.CertificateApplicabilityRule;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.aov.AlgorithmObsolescenceValidation;
import eu.europa.esig.dss.validation.process.bbb.aov.RevocationDataAlgorithmObsolescenceValidation;
import eu.europa.esig.dss.validation.process.bbb.aov.SignatureAlgorithmObsolescenceValidation;
import eu.europa.esig.dss.validation.process.bbb.aov.checks.AlgorithmObsolescenceValidationCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.RevocationFreshnessChecker;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationDataRequiredCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationFreshnessCheckerResultCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.BestSignatureTimeNotBeforeCertificateIssuanceCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.pcv.PastCertificateValidation;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.BestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpirationCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.CurrentTimeIndicationCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.POEExistsCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.POENotAfterCARevocationTimeCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.PastCertificateValidationAcceptableCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.PastRevocationDataValidationConclusiveCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.PastSignatureValidationCertificateRevocationSelectorResultCheck;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Performs the "5.6.2.4 Past signature validation building block"
 *
 */
public class PastSignatureValidation extends Chain<XmlPSV> {

	/** Token to check */
	private final TokenProxy token;

	/** Map of all BBBs */
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	/** Current conclusion */
	private final XmlConclusion currentConclusion;

	/** POE container */
	private final POEExtraction poe;

	/** Validation time */
	private final Date currentTime;

	/** Validation policy */
	private final ValidationPolicy policy;

	/** Validation context */
	private final Context context;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param token {@link TokenProxy}
	 * @param bbbs map of all BBSs
	 * @param currentConclusion {@link XmlConclusion}
	 * @param poe {@link POEExtraction}
	 * @param currentTime {@link Date}
	 * @param policy {@link ValidationPolicy}
	 * @param context {@link Context}
	 */
	public PastSignatureValidation(I18nProvider i18nProvider, TokenProxy token, Map<String, XmlBasicBuildingBlocks> bbbs,
			XmlConclusion currentConclusion, POEExtraction poe, Date currentTime, ValidationPolicy policy, Context context) {
		super(i18nProvider, new XmlPSV());
		this.token = token;
		this.bbbs = bbbs;
		this.currentConclusion = currentConclusion;
		this.poe = poe;
		this.currentTime = currentTime;
		this.policy = policy;
		this.context = context;
	}
    
	@Override
	protected MessageTag getTitle() {
		return MessageTag.PAST_SIGNATURE_VALIDATION;
	}
	
	@Override
	protected void initChain() {

		XmlBasicBuildingBlocks tokenBBB = bbbs.get(token.getId());

		ChainItem<XmlPSV> item = null;

		/*
		 * 1) The building block shall verify that there is at least one revocation data instance
		 * that is known to contain revocation status information about the signing certificate
		 * for which the set of POEs contains a POE for the signing certificate issuer's certificate
		 * after the issuance date and before the expiration date of the signing certificate issuer's certificate:
		 *
		 * a. If there is such a revocation data, the building block shall remove from the Certificate
		 *    Validation Data all revocation data known to contain revocation status information about
		 *    the signing certificate for which there is no such POE and set sig_cert_revocation_poe-status to PASSED.
		 *
		 * b. Otherwise the building block shall set sig_cert_revocation_poe-status to INDETERMINATE with
		 *    the sub-indication REVOCATION_OUT_OF_BOUNDS_NO_POE.
		 */

		final CertificateWrapper signingCertificate = token.getSigningCertificate();

		XmlConclusion sigCertRevocationPoeStatus = new XmlConclusion();
		List<CertificateRevocationWrapper> signingCertificateRevocations = Collections.emptyList();

		if (isRevocationDataRequired(signingCertificate, SubContext.SIGNING_CERT)) {
			PastSignatureValidationCertificateRevocationSelector certificateRevocationSelector =
					new PastSignatureValidationCertificateRevocationSelector(
							i18nProvider, signingCertificate, currentTime, bbbs, token.getId(), poe, policy);

			XmlCRS xmlCRS = certificateRevocationSelector.execute();
			tokenBBB.setPSVCRS(xmlCRS);

			item = firstItem = checkCertificateRevocationSelectorResult(xmlCRS);

			signingCertificateRevocations = certificateRevocationSelector.getAcceptableCertificateRevocations();
			if (Utils.isCollectionNotEmpty(signingCertificateRevocations)) {
				sigCertRevocationPoeStatus.setIndication(Indication.PASSED);
			} else {
				sigCertRevocationPoeStatus.setIndication(Indication.INDETERMINATE);
				sigCertRevocationPoeStatus.setSubIndication(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE);
				// keep all revocation data if none of the valid instances found
				signingCertificateRevocations = signingCertificate.getCertificateRevocationData();
			}

		} else {
			// revocation check is not required
			sigCertRevocationPoeStatus.setIndication(Indication.PASSED);
		}

		/*
		 * 2) The building block shall perform the past certificate validation process specified
		 * in clause 5.6.2.1  with the following inputs: the signature, the target certificate,
		 * the X.509 validation parameters, certificate validation data, X.509 validation constraints,
		 * cryptographic constraints and the set of POEs. If it returns PASSED/validation time,
		 * the building block shall go to the next step. Otherwise, the building block shall return
		 * the current time status and sub indication with an explanation of the failure.
		 */
		PastCertificateValidation pcv = new PastCertificateValidation(i18nProvider, token, bbbs, poe, currentTime, policy, context);
		XmlPCV pcvResult = pcv.execute();
		tokenBBB.setPCV(pcvResult);

		ChainItem<XmlPSV> pastCertificateValidationAcceptableCheck = pastCertificateValidationAcceptableCheck(pcvResult);
		if (item == null) {
			item = firstItem = pastCertificateValidationAcceptableCheck;
		} else {
			item = item.setNextItem(pastCertificateValidationAcceptableCheck);
		}

		Date controlTime = pcvResult.getControlTime();
		result.setControlTime(controlTime);

		/*
		 * 3) If there is a POE of the signature value at (or before) the validation time returned in the previous step:
		 */
		POEExistsCheck poeExistsCheck = poeExist(controlTime);

		item = item.setNextItem(poeExist(controlTime));

		Date bestSignatureTime = poe.getLowestPOETime(token.getId());

		boolean poeExists = poeExistsCheck.process();
		/*
		 * - If current time indication/sub indication is INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND_NO_POE:
		 */
		if (poeExists && Indication.INDETERMINATE.equals(currentConclusion.getIndication())
				&& SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE.equals(currentConclusion.getSubIndication())) {
			/*
			 * a) If best-signature-time is before the issuance date of the signing certificate (notBefore field), the
			 *    building block shall return the indication FAILED with the sub-indication NOT_YET_VALID.
			 * b) If best-signature-time is after the expiration date of the signing certificate, the building block shall
			 *    return the indication INDETERMINATE with the sub-indication OUT_OF_BOUNDS_NO_POE.
			 * c) Else the building block shall go to step 7).
			 */

			item = item.setNextItem(bestSignatureTimeNotBeforeCertificateIssuance(bestSignatureTime, signingCertificate));

			item = item.setNextItem(bestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpiration(
					bestSignatureTime, signingCertificate, SubIndication.OUT_OF_BOUNDS_NO_POE));

		}

		/*
		 * - If current time indication/sub-indication is INDETERMINATE/REVOKED_NO_POE,
		 *   INDETERMINATE/REVOCATION_OUT_OF_BOUNDS_NO_POE or INDETERMINATE/TRY_LATER
		 *   because the certificate has been found to be suspended, then:
		 */
		else if (poeExists && Indication.INDETERMINATE.equals(currentConclusion.getIndication())
				&& (SubIndication.REVOKED_NO_POE.equals(currentConclusion.getSubIndication())
						|| SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE.equals(currentConclusion.getSubIndication())
						|| (SubIndication.TRY_LATER.equals(currentConclusion.getSubIndication()) && isCertificateSuspended()))) {
			/*
			 * a) If best-signature-time is before the issuance date of the signing certificate,
			 *    the process shall return the indication FAILED with the sub-indication NOT_YET_VALID
			 * b) If best-signature-time is within the validity period of the signing certificate,
			 *    the building block shall go to step 7).
			 * c) Otherwise the building block shall set the current time indication/sub-indication to
			 *    INDETERMINATE/OUT_OF_BOUNDS_NOT_REVOKED and continue the process.
			 */

			item = item.setNextItem(bestSignatureTimeNotBeforeCertificateIssuance(bestSignatureTime, signingCertificate));

			item = item.setNextItem(bestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpiration(
					bestSignatureTime, signingCertificate, SubIndication.OUT_OF_BOUNDS_NOT_REVOKED));

		}

		/*
		 * - If current time indication/sub-indication is INDETERMINATE/REVOKED_CA_NO_POE then:
		 */
		else if (poeExists && Indication.INDETERMINATE.equals(currentConclusion.getIndication())
				&& SubIndication.REVOKED_CA_NO_POE.equals(currentConclusion.getSubIndication())) {
			/*
			 * a) If there is a POE for the revocation data containing the revocation status information
			 *    of the signer certificate at (or before) the revocation time of the CA certificate, then:
			 *    i.  If best signature time (lowest time at which there exists a POE for the signature value
			 *        in the set of POEs) is within the validity period of the signing certificate,
			 *        the building block shall go to step 7).
			 *    ii. Otherwise the building block shall set the current time indication/sub-indication to
			 *        OUT_OF_BOUNDS_NOT_REVOKED and continue the process.
			 * b) Otherwise, the building block shall return with the indication INDETERMINATE and the
			 *    sub-indication REVOKED_CA_NO_POE.
			 */

			CertificateWrapper caCertificate = signingCertificate.getSigningCertificate();
			CertificateRevocationWrapper latestCARevocationData = caCertificate == null ? null :
					ValidationProcessUtils.getLatestAcceptableRevocationData(token, caCertificate,
							caCertificate.getCertificateRevocationData(), currentTime, bbbs, poe);
			if (latestCARevocationData != null) {
				item = item.setNextItem(poeExistNotAfterCARevocationTimeCheck(signingCertificateRevocations, latestCARevocationData.getRevocationDate()));
			}

			// NOTE: executed as a part of the check below (see "continue the process" reference)
			item = item.setNextItem(bestSignatureTimeNotBeforeCertificateIssuance(bestSignatureTime, signingCertificate));

			item = item.setNextItem(bestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpiration(
					bestSignatureTime, signingCertificate, SubIndication.OUT_OF_BOUNDS_NOT_REVOKED));

		}

		/*
		 * - If current time indication/sub-indication is INDETERMINATE/OUT_OF_BOUNDS_NO_POE or OUT_OF_BOUNDS_NOT_REVOKED:
		 *
		 * a) If best-signature-time (lowest time at which there exists a POE for the signature value in the set of POEs)
		 *    is before the issuance date of the signing certificate (notBefore field), the building block shall
		 *    return the indication FAILED with the sub-indication NOT_YET_VALID.
		 *
		 * b) If best-signature-time (lowest time at which there exists a POE for the signature value in the set of POEs)
		 *    is after the issuance date and before the expiration date of the signing certificate,
		 *    the building block shall go to step 7.
		 */
		else if (poeExists && Indication.INDETERMINATE.equals(currentConclusion.getIndication())
				&& (SubIndication.OUT_OF_BOUNDS_NO_POE.equals(currentConclusion.getSubIndication())
						|| SubIndication.OUT_OF_BOUNDS_NOT_REVOKED.equals(currentConclusion.getSubIndication()))) {

			item = item.setNextItem(bestSignatureTimeNotBeforeCertificateIssuance(bestSignatureTime, signingCertificate));

			item = item.setNextItem(bestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpiration(bestSignatureTime,
					signingCertificate, currentConclusion.getSubIndication()));

		}

		/*
		 * 4) If current time indication/ sub-indication is INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE and for
		 * each algorithm (or key size) in the list concerned by the failure, there is a POE for the material that
		 * uses this algorithm (or key size) at a time before the time up to which the algorithm in question was
		 * considered secure, the building block shall go to step 7).
		 */
		else if (Indication.INDETERMINATE.equals(currentConclusion.getIndication())
				&& SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(currentConclusion.getSubIndication())) {

			item = item.setNextItem(algorithmsObsolescenceValidation());

			item = revocationDataAlgorithmsObsolescenceValidation(item, signingCertificateRevocations);

		}

		/*
		 * 5) If current time indication/sub indication is INDETERMINATE/TRY_LATER because
		 * the revocation information of the target certificate was not fresh enough:
		 */
		else if (Indication.INDETERMINATE.equals(currentConclusion.getIndication())
				&& SubIndication.TRY_LATER.equals(currentConclusion.getSubIndication()) && !isCertificateSuspended()) {
			/*
		     * a) The building block shall determine from the set of POEs the earliest time at which
			 *    the existence of the signature can be proven.
			 * b) The building block shall run the Revocation Freshness Checker (clause 5.2.5) with
			 *    the corresponding revocation status information, the target certificate and the time
			 *    determined in step a) above.
			 * c) If the checker returns PASSED, the building block shall go to step 7). Otherwise,
		     *    the building block shall return the indication INDETERMINATE, the sub indication
		     *    TRY_LATER and, if returned from the Revocation Freshness Checker, the suggestion
			 *    for when to try the validation again.
		     */
			item = revocationIsFresh(item, bestSignatureTime);
		}

		/*
		 * 6) In all other cases, the building block shall return the current time indication/sub-indication
		 * together with an explanation of the failure.
		 */
		else {
			item = item.setNextItem(currentTimeIndicationCheck());
		}

		/*
		 * 7) The building block shall return the indication and sub-indication contained
		 * in sig_cert_revocation_poe-status.
		 */
		item = item.setNextItem(pastRevocationDataValidationConclusive(sigCertRevocationPoeStatus));

	}

	private boolean isRevocationDataRequired(CertificateWrapper certificate, SubContext subContext) {
		CertificateApplicabilityRule constraint = policy.getRevocationDataSkipConstraint(context, subContext);
		LevelRule sunsetDateConstraint = policy.getCertificateSunsetDateConstraint(context, subContext);
		return new RevocationDataRequiredCheck<>(i18nProvider, result, certificate, getLowestPoeTime(certificate), sunsetDateConstraint, constraint).process();
	}

	private ChainItem<XmlPSV> checkCertificateRevocationSelectorResult(XmlCRS crsResult) {
		return new PastSignatureValidationCertificateRevocationSelectorResultCheck(i18nProvider, result, crsResult, getWarnLevelRule());
	}

	private ChainItem<XmlPSV> currentTimeIndicationCheck() {
		return new CurrentTimeIndicationCheck(i18nProvider, result, currentConclusion.getIndication(),
				currentConclusion.getSubIndication(), currentConclusion.getErrors(), getFailLevelRule());
	}

	private ChainItem<XmlPSV> pastCertificateValidationAcceptableCheck(XmlPCV pcvResult) {
		return new PastCertificateValidationAcceptableCheck(i18nProvider, result, pcvResult, token.getId(),
				currentConclusion.getIndication(), currentConclusion.getSubIndication(), getFailLevelRule());
	}

	private POEExistsCheck poeExist(Date controlTime) {
		return new POEExistsCheck(i18nProvider, result, token, controlTime, poe, getWarnLevelRule());
	}

	private ChainItem<XmlPSV> poeExistNotAfterCARevocationTimeCheck(Collection<CertificateRevocationWrapper> certificateRevocations,
																	Date caRevocationTime) {
		return new POENotAfterCARevocationTimeCheck<>(i18nProvider, result, certificateRevocations,
				caRevocationTime, poe, getFailLevelRule());
	}

	private ChainItem<XmlPSV> pastRevocationDataValidationConclusive(XmlConclusion currentConclusion) {
		LevelRule constraint = ValidationProcessUtils.getConstraintOrMaxLevel(
				policy.getRevocationIssuerNotExpiredConstraint(context, SubContext.SIGNING_CERT), Level.FAIL);
		return new PastRevocationDataValidationConclusiveCheck(i18nProvider, result, currentConclusion, constraint);
	}

	private ChainItem<XmlPSV> bestSignatureTimeNotBeforeCertificateIssuance(Date bestSignatureTime, CertificateWrapper signingCertificate) {
		return new BestSignatureTimeNotBeforeCertificateIssuanceCheck<>(i18nProvider, result, bestSignatureTime, signingCertificate,
				getFailLevelRule());
	}

	private ChainItem<XmlPSV> bestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpiration(Date bestSignatureTime,
			CertificateWrapper signingCertificate, SubIndication currentTimeSubIndication) {
		return new BestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpirationCheck(i18nProvider, result, bestSignatureTime, signingCertificate,
				currentTimeSubIndication, getFailLevelRule());
	}

	private ChainItem<XmlPSV> algorithmsObsolescenceValidation() {
		Date lowestPoeTime = getLowestPoeTime(token);

		AlgorithmObsolescenceValidation<?> algorithmObsolescenceValidation =
				new SignatureAlgorithmObsolescenceValidation<>(i18nProvider, token, context, lowestPoeTime, policy);
		XmlAOV aovResult = algorithmObsolescenceValidation.execute();

		MessageTag position = ValidationProcessUtils.getCryptoPosition(context);

		return new AlgorithmObsolescenceValidationCheck<>(i18nProvider, result, aovResult, lowestPoeTime, position, token.getId());
	}

	private ChainItem<XmlPSV> revocationDataAlgorithmsObsolescenceValidation(ChainItem<XmlPSV> item, List<CertificateRevocationWrapper> signingCertificateRevocations) {
		return revocationDataAlgorithmsObsolescenceValidation(item, token.getCertificateChain(), signingCertificateRevocations, context, new ArrayList<>());
	}

	private ChainItem<XmlPSV> revocationDataAlgorithmsObsolescenceValidation(ChainItem<XmlPSV> item, List<CertificateWrapper> certificateChain,
			List<CertificateRevocationWrapper> signingCertificateRevocations, Context context, List<String> checkedTokens) {
		for (CertificateWrapper certificate : certificateChain) {
			final SubContext subContext = token.getSigningCertificate().getId().equals(certificate.getId()) ?
					SubContext.SIGNING_CERT : SubContext.CA_CERTIFICATE;
			final Date certificatePoeTime = getLowestPoeTime(certificate);
			if (isTrustAnchor(certificate, certificatePoeTime, context, subContext)) {
				break;
			}
			if (checkedTokens.contains(certificate.getId())) {
				continue;
			}
			checkedTokens.add(certificate.getId());

			final List<CertificateRevocationWrapper> revocationData = SubContext.SIGNING_CERT.equals(subContext) ?
					signingCertificateRevocations : certificate.getCertificateRevocationData();

			CertificateRevocationWrapper latestAcceptableRevocation =
					ValidationProcessUtils.getLatestAcceptableRevocationData(token, certificate, revocationData, currentTime, bbbs, poe);
			if (latestAcceptableRevocation != null && !checkedTokens.contains(latestAcceptableRevocation.getId())) {
				checkedTokens.add(latestAcceptableRevocation.getId());

				Date revocationPoeTime = getLowestPoeTime(certificate);

				AlgorithmObsolescenceValidation<?> algorithmObsolescenceValidation =
						new RevocationDataAlgorithmObsolescenceValidation(i18nProvider, latestAcceptableRevocation, revocationPoeTime, policy);
				XmlAOV aovResult = algorithmObsolescenceValidation.execute();

				MessageTag position = ValidationProcessUtils.getCryptoPosition(Context.REVOCATION);

				item = item.setNextItem(new AlgorithmObsolescenceValidationCheck<>(i18nProvider, result, aovResult, revocationPoeTime, position, token.getId()));

				item = revocationDataAlgorithmsObsolescenceValidation(item, latestAcceptableRevocation.getCertificateChain(),
						signingCertificateRevocations, Context.REVOCATION, checkedTokens);

			}

		}
		return item;
	}

	private boolean isTrustAnchor(CertificateWrapper certificateWrapper, Date controlTime, Context context, SubContext subContext) {
		LevelRule constraint = policy.getCertificateSunsetDateConstraint(context, subContext);
		return ValidationProcessUtils.isTrustAnchor(certificateWrapper, controlTime, constraint);
	}

	private ChainItem<XmlPSV> revocationIsFresh(ChainItem<XmlPSV> item, Date bestSignatureTime) {
		for (CertificateWrapper certificate : token.getCertificateChain()) {
			SubContext subContext = getSubContext(certificate);
			if (isRevocationDataRequired(certificate, subContext)) {
				PastSignatureValidationCertificateRevocationSelector certificateRevocationSelector =
						new PastSignatureValidationCertificateRevocationSelector(
								i18nProvider, certificate, currentTime, bbbs, token.getId(), poe, policy);

				certificateRevocationSelector.execute();
				CertificateRevocationWrapper latestCertificateRevocation = certificateRevocationSelector.getLatestAcceptableCertificateRevocation();

				RevocationFreshnessChecker rfc = new RevocationFreshnessChecker(i18nProvider, latestCertificateRevocation,
						bestSignatureTime, context, subContext, policy);
				XmlRFC xmlRFC = rfc.execute();
				item = item.setNextItem(checkRevocationFreshnessCheckerResult(xmlRFC));
			}
		}
		return item;
	}

	private SubContext getSubContext(CertificateWrapper certificateWrapper) {
		return token.getSigningCertificate().getId().equals(certificateWrapper.getId()) ?
				SubContext.SIGNING_CERT : SubContext.CA_CERTIFICATE;
	}

	private ChainItem<XmlPSV> checkRevocationFreshnessCheckerResult(XmlRFC rfcResult) {
		return new RevocationFreshnessCheckerResultCheck<XmlPSV>(i18nProvider, result, rfcResult, getFailLevelRule()) {
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
	
	private Date getLowestPoeTime(TokenProxy token) {
		return poe.getLowestPOETime(token.getId());
	}

	private boolean isCertificateSuspended() {
		for (CertificateWrapper certificate : token.getCertificateChain()) {
			final SubContext subContext = token.getSigningCertificate().getId().equals(certificate.getId()) ?
					SubContext.SIGNING_CERT : SubContext.CA_CERTIFICATE;
			if (isTrustAnchor(certificate, currentTime, context, subContext)) {
				break;
			}
			List<CertificateRevocationWrapper> revocationData = certificate.getCertificateRevocationData();
			CertificateRevocationWrapper latestRevocationData = ValidationProcessUtils
					.getLatestAcceptableRevocationData(token, certificate, revocationData, currentTime, bbbs, poe);
			if (latestRevocationData != null && latestRevocationData.isRevoked()
					&& RevocationReason.CERTIFICATE_HOLD.equals(latestRevocationData.getReason())) {
				return true;
			}
		}
		return false;
	}

	@Override
	protected void collectMessages(XmlConclusion conclusion, XmlConstraint constraint) {
		if (XmlBlockType.PCV == constraint.getBlockType()) {
			// skip PCV POE message extraction
		} else if (XmlBlockType.PSV_CRS == constraint.getBlockType()) {
			// skip acceptable revocation message extraction
		} else {
			super.collectMessages(conclusion, constraint);
		}
	}

}
