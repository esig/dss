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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
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
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.DigestMatcherCryptographicCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.SigningCertificateDigestAlgorithmCheck;
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
		 * 1) The building block shall verify that there is at least one revocation information instance
		 * that is known to contain revocation information about the signing certificate for which
		 * the set of POEs contains a POE for the certificate of its issuer after the issuance date and
		 * before the expiration date of that certificate:
		 *
		 * a. If there is such a revocation information, the building block shall remove from
		 *    the Certificate Validation Data all revocation information known to contain revocation information
		 *    about the signing certificate for which there is no such POE and
		 *    set sig_cert_revocation_poe-status to PASSED.
		 *
		 * b. Otherwise the building block shall set sig_cert_revocation_poe-status to INDETERMINATE with
		 *    the sub-indication REVOCATION_OUT_OF_BOUNDS_NO_POE.
		 */

		final CertificateWrapper signingCertificate = token.getSigningCertificate();

		PastSignatureValidationCertificateRevocationSelector certificateRevocationSelector =
				new PastSignatureValidationCertificateRevocationSelector(
						i18nProvider, signingCertificate, currentTime, bbbs, token.getId(), poe, policy);

		XmlCRS xmlCRS = certificateRevocationSelector.execute();
		tokenBBB.setPSVCRS(xmlCRS);

		item = firstItem = checkCertificateRevocationSelectorResult(xmlCRS);

		XmlConclusion sigCertRevocationPoeStatus = new XmlConclusion();

		List<CertificateRevocationWrapper> signingCertificateRevocations = certificateRevocationSelector.getAcceptableCertificateRevocations();
		if (Utils.isCollectionNotEmpty(signingCertificateRevocations)) {
			sigCertRevocationPoeStatus.setIndication(Indication.PASSED);
		} else {
			sigCertRevocationPoeStatus.setIndication(Indication.INDETERMINATE);
			sigCertRevocationPoeStatus.setSubIndication(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE);
			// keep all revocation data if none of the valid instances found
			signingCertificateRevocations = signingCertificate.getCertificateRevocationData();
		}

		/*
		 * 2) The building block shall perform the past certificate validation process with the following inputs:
		 * the signature, the target certificate, the X.509 validation parameters, certificate validation data, chain
		 * constraints, cryptographic constraints and the set of POEs. If it returns PASSED/validation time, the
		 * building block shall go to the next step. Otherwise, the building block shall return the current time status
		 * and sub-indication with an explanation of the failure.
		 */
		PastCertificateValidation pcv = new PastCertificateValidation(i18nProvider, token, bbbs, poe, currentTime, policy, context);
		XmlPCV pcvResult = pcv.execute();
		tokenBBB.setPCV(pcvResult);

		item = item.setNextItem(pastCertificateValidationAcceptableCheck(pcvResult));

		Date controlTime = pcvResult.getControlTime();
		result.setControlTime(controlTime);

		/*
		 * 3) If there is a POE of the signature value at (or before) the validation time returned in the previous step:
		 */
		boolean poeExists = controlTime != null && poe.isPOEExists(token.getId(), controlTime);
		if (poeExists) {
			item = item.setNextItem(poeExist());
		}

		/*
		 * - If current time indication/sub-indication is INDETERMINATE/REVOKED_NO_POE or
		 *   INDETERMINATE/REVOCATION_OUT_OF_BOUNDS_NO_POE, the building block shall go to step 6.
		 */
		if (poeExists && Indication.INDETERMINATE.equals(currentConclusion.getIndication())
				&& (SubIndication.REVOKED_NO_POE.equals(currentConclusion.getSubIndication())
						|| SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE.equals(currentConclusion.getSubIndication()))) {
			// continue
		}

		/*
		 * - If current time indication/sub-indication is INDETERMINATE/REVOKED_CA_NO_POE and
		 *   there is a POE for the revocation information of the signer certificate at (or before)
		 *   the revocation time of the CA certificate, the building block shall go to step 6.
		 *   Otherwise, the building block shall return with the indication INDETERMINATE and
		 *   the sub-indication REVOKED_CA_NO_POE.
		 */
		else if (poeExists && Indication.INDETERMINATE.equals(currentConclusion.getIndication())
				&& SubIndication.REVOKED_CA_NO_POE.equals(currentConclusion.getSubIndication())) {
			CertificateWrapper caCertificate = signingCertificate.getSigningCertificate();
			CertificateRevocationWrapper latestCARevocationData = caCertificate == null ? null :
					ValidationProcessUtils.getLatestAcceptableRevocationData(token, caCertificate,
							caCertificate.getCertificateRevocationData(), currentTime, bbbs, poe);
			if (latestCARevocationData != null) {
				item = item.setNextItem(poeExistNotAfterCARevocationTimeCheck(signingCertificateRevocations, latestCARevocationData.getRevocationDate()));
			}

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
		 *    the building block shall go to step 6.
		 */
		else if (poeExists && Indication.INDETERMINATE.equals(currentConclusion.getIndication())
				&& (SubIndication.OUT_OF_BOUNDS_NO_POE.equals(currentConclusion.getSubIndication())
						|| SubIndication.OUT_OF_BOUNDS_NOT_REVOKED.equals(currentConclusion.getSubIndication()))) {

			Date bestSignatureTime = poe.getLowestPOETime(token.getId());

			item = item.setNextItem(bestSignatureTimeNotBeforeCertificateIssuance(bestSignatureTime, signingCertificate));

			item = item.setNextItem(bestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpiration(bestSignatureTime,
					signingCertificate, currentConclusion.getSubIndication()));

		}

		/*
		 * 4) If current time indication/ sub-indication is INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE and for
		 * each algorithm (or key size) in the list concerned by the failure, there is a POE for the material that
		 * uses this algorithm (or key size) at a time before the time up to which the algorithm in question was
		 * considered secure, the building block shall go to step 6).
		 */
		else if (Indication.INDETERMINATE.equals(currentConclusion.getIndication())
				&& SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(currentConclusion.getSubIndication())) {
			CryptographicConstraint cryptographicConstraint = policy.getSignatureCryptographicConstraint(context);
			Date lowestPoeTime = getLowestPoeTime(token);

			// check signature or timestamp itself
			item = item.setNextItem(tokenUsedAlgorithmsAreSecureAtPoeTime(token, lowestPoeTime,
					ValidationProcessUtils.getCryptoPosition(context), cryptographicConstraint));

			if (Utils.isCollectionNotEmpty(token.getDigestMatchers())) {
				for (XmlDigestMatcher digestMatcher : token.getDigestMatchers()) {
					item = item.setNextItem(digestMatcherIsSecureAtPoeTime(digestMatcher, lowestPoeTime, cryptographicConstraint));
				}
			}

			for (CertificateRefWrapper certificateRef : token.getSigningCertificateReferences()) {
				item = item.setNextItem(signCertRefIsSecureAtPoeTime(certificateRef, lowestPoeTime, context));
			}

			// check the certificate chain and its revocation data
			item = certificateChainReliableAtPoeTime(item, signingCertificateRevocations, context);

		}

		/*
		 * 5) In all other cases, the building block shall return the current time indication/sub-indication together
		 * with an explanation of the failure.
		 */
		else {
			item = item.setNextItem(currentTimeIndicationCheck());
		}

		/*
		 * 6) The building block shall return the indication and sub-indication contained
		 * in sig_cert_revocation_poe-status.
		 */
		item = item.setNextItem(pastRevocationDataValidationConclusive(sigCertRevocationPoeStatus));

	}

	private ChainItem<XmlPSV> checkCertificateRevocationSelectorResult(XmlCRS crsResult) {
		return new PastSignatureValidationCertificateRevocationSelectorResultCheck(i18nProvider, result, crsResult, getWarnLevelConstraint());
	}

	private ChainItem<XmlPSV> currentTimeIndicationCheck() {
		return new CurrentTimeIndicationCheck(i18nProvider, result, currentConclusion.getIndication(),
				currentConclusion.getSubIndication(), currentConclusion.getErrors(), getFailLevelConstraint());
	}

	private ChainItem<XmlPSV> pastCertificateValidationAcceptableCheck(XmlPCV pcvResult) {
		return new PastCertificateValidationAcceptableCheck(i18nProvider, result, pcvResult, token.getId(),
				currentConclusion.getIndication(), currentConclusion.getSubIndication(), getFailLevelConstraint());
	}

	private ChainItem<XmlPSV> poeExist() {
		return new POEExistsCheck(i18nProvider, result, getFailLevelConstraint());
	}

	private ChainItem<XmlPSV> poeExistNotAfterCARevocationTimeCheck(Collection<CertificateRevocationWrapper> certificateRevocations,
																	Date caRevocationTime) {
		return new POENotAfterCARevocationTimeCheck<>(i18nProvider, result, certificateRevocations,
				caRevocationTime, poe, getFailLevelConstraint());
	}

	private ChainItem<XmlPSV> pastRevocationDataValidationConclusive(XmlConclusion currentConclusion) {
		return new PastRevocationDataValidationConclusiveCheck(i18nProvider, result, currentConclusion, getFailLevelConstraint());
	}

	private ChainItem<XmlPSV> bestSignatureTimeNotBeforeCertificateIssuance(Date bestSignatureTime, CertificateWrapper signingCertificate) {
		return new BestSignatureTimeNotBeforeCertificateIssuanceCheck<>(i18nProvider, result, bestSignatureTime, signingCertificate,
				getFailLevelConstraint());
	}

	private ChainItem<XmlPSV> bestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpiration(Date bestSignatureTime,
			CertificateWrapper signingCertificate, SubIndication currentTimeSubIndication) {
		return new BestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpirationCheck(i18nProvider, result, bestSignatureTime, signingCertificate,
				currentTimeSubIndication, getFailLevelConstraint());
	}

	private CryptographicCheck<XmlPSV> tokenUsedAlgorithmsAreSecureAtPoeTime(
			TokenProxy currentToken, Date validationDate, MessageTag position, CryptographicConstraint constraint) {
		return new CryptographicCheck<>(i18nProvider, result, currentToken,  position, validationDate, constraint);
	}
	
	private ChainItem<XmlPSV> digestMatcherIsSecureAtPoeTime(XmlDigestMatcher digestMatcher, Date validationDate, 
			CryptographicConstraint constraint) {
		MessageTag position = ValidationProcessUtils.getDigestMatcherCryptoPosition(digestMatcher);
		return new DigestMatcherCryptographicCheck<>(i18nProvider, digestMatcher.getDigestMethod(), result, validationDate, position, constraint);
	}

	private ChainItem<XmlPSV> signCertRefIsSecureAtPoeTime(
			CertificateRefWrapper signCertReference, Date validationDate, Context context) {
		SubContext subContext;
		if (token.getSigningCertificate() != null &&
				token.getSigningCertificate().getId().equals(signCertReference.getCertificateId())) {
			subContext = SubContext.SIGNING_CERT;
		} else {
			subContext = SubContext.CA_CERTIFICATE;
		}

		CryptographicConstraint cryptographicConstraint = policy.getCertificateCryptographicConstraint(context, subContext);

		LevelConstraint constraint = policy.getSigningCertificateDigestAlgorithmConstraint(context);
		return new SigningCertificateDigestAlgorithmCheck<>(i18nProvider, signCertReference, result, validationDate,
				cryptographicConstraint, constraint);
	}
	
	private ChainItem<XmlPSV> certificateChainReliableAtPoeTime(ChainItem<XmlPSV> item,
			List<CertificateRevocationWrapper> signingCertificateRevocations, Context context) {
		return certificateChainReliableAtPoeTime(item, token.getCertificateChain(), signingCertificateRevocations, context, new ArrayList<>());
	}
	
	private ChainItem<XmlPSV> certificateChainReliableAtPoeTime(ChainItem<XmlPSV> item, List<CertificateWrapper> certificateChain,
			List<CertificateRevocationWrapper> signingCertificateRevocations, Context context, List<String> checkedTokens) {
		for (CertificateWrapper certificate : certificateChain) {
			if (certificate.isTrusted()) {
				break;
			}
			if (checkedTokens.contains(certificate.getId())) {
				continue;
			}
			checkedTokens.add(certificate.getId());
			
			final SubContext subContext = token.getSigningCertificate().getId().equals(certificate.getId()) ?
					SubContext.SIGNING_CERT : SubContext.CA_CERTIFICATE;
			final List<CertificateRevocationWrapper> revocationData = SubContext.SIGNING_CERT.equals(subContext) ?
					signingCertificateRevocations : certificate.getCertificateRevocationData();

			Date certificatePoeTime = getLowestPoeTime(certificate);

			item = item.setNextItem(tokenUsedAlgorithmsAreSecureAtPoeTime(certificate, certificatePoeTime,
					ValidationProcessUtils.getCertificateChainCryptoPosition(context), policy.getCertificateCryptographicConstraint(context, subContext)));
			
			CertificateRevocationWrapper latestAcceptableRevocation =
					ValidationProcessUtils.getLatestAcceptableRevocationData(token, certificate, revocationData, currentTime, bbbs, poe);
			if (latestAcceptableRevocation != null && !checkedTokens.contains(latestAcceptableRevocation.getId())) {
				checkedTokens.add(latestAcceptableRevocation.getId());

				Date revocationPoeTime = getLowestPoeTime(certificate);
				
				item = item.setNextItem(tokenUsedAlgorithmsAreSecureAtPoeTime(latestAcceptableRevocation, revocationPoeTime,
						ValidationProcessUtils.getCertificateChainCryptoPosition(Context.REVOCATION),
						policy.getSignatureCryptographicConstraint(Context.REVOCATION)));
				
				item = certificateChainReliableAtPoeTime(item, latestAcceptableRevocation.getCertificateChain(),
						signingCertificateRevocations, Context.REVOCATION, checkedTokens);

			}
			
		}
		return item;
	}
	
	private Date getLowestPoeTime(TokenProxy token) {
		return poe.getLowestPOETime(token.getId());
	}

}
