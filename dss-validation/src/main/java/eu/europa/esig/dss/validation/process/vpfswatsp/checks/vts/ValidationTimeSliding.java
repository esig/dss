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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts;

import eu.europa.esig.dss.detailedreport.jaxb.XmlAOV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicValidation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVTS;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.SubContext;
import eu.europa.esig.dss.enumerations.ValidationModel;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.CertificateApplicabilityRule;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.aov.CertificateAlgorithmObsolescenceValidation;
import eu.europa.esig.dss.validation.process.bbb.aov.RevocationDataAlgorithmObsolescenceValidation;
import eu.europa.esig.dss.validation.process.bbb.xcv.crs.CertificateRevocationSelector;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.RevocationFreshnessChecker;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationDataRequiredCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks.ControlTimeCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks.SatisfyingRevocationDataExistsCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks.SunsetDateCheck;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Performs Validation Time Sliding process
 */
public class ValidationTimeSliding extends Chain<XmlVTS> {

	/** Token to process */
	private final TokenProxy token;

	/** Certificate representing a trust anchor */
	private final CertificateWrapper trustedCertificate;

	/** Validation time */
	private final Date currentTime;

	/** Map of all BBBs */
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	/** Validation context */
	private final Context context;

	/** POE container */
	private final POEExtraction poe;

	/** Validation policy */
	private final ValidationPolicy policy;

	/** Validation time */
	private Date controlTime;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param token {@link TokenProxy}
	 * @param trustedCertificate {@link CertificateWrapper}
	 * @param currentTime {@link Date}
	 * @param poe {@link POEExtraction}
	 * @param bbbs a map of {@link XmlBasicBuildingBlocks}
	 * @param context {@link Context}
	 * @param policy {@link ValidationPolicy}
	 */
	public ValidationTimeSliding(I18nProvider i18nProvider, TokenProxy token, CertificateWrapper trustedCertificate,
								 Date currentTime, POEExtraction poe, Map<String, XmlBasicBuildingBlocks> bbbs,
								 Context context, ValidationPolicy policy) {
		super(i18nProvider, new XmlVTS());

		this.token = token;
		this.trustedCertificate = trustedCertificate;
		this.currentTime = currentTime;
		this.bbbs = bbbs;

		this.context = context;

		this.poe = poe;
		this.policy = policy;
	}
    
	@Override
	protected MessageTag getTitle() {
		return MessageTag.VALIDATION_TIME_SLIDING;
	}

	@Override
	protected void initChain() {

		final XmlBasicBuildingBlocks tokenBBB = bbbs.get(token.getId());

		ChainItem<XmlVTS> item = null;

		/*
		 * 5.6.2.2.4 Processing
		 * 
		 * 1) The building block shall initialize control-time to either:
		 *
		 * a) the trust anchor sunset date when this input is provided, and this date is 
		 *    before current date/time; or
		 * b) the current date/time in all other cases. 
		 * 
		 * NOTE 1: Control-time is an internal variable that is used within the
		 * algorithms and not part of the core results of the validation
		 * process.
		 * 
		 * NOTE 2: Initializing control time with current date/time assumes that 
		 * the trust anchor is still trusted at the current date/time. The algorithm 
		 * can capture the very exotic case where the trust anchor is broken (or becomes 
		 * untrusted for any other reason) at a known date by initializing control time 
		 * to this date/time. 
		 */
		if (trustedCertificate != null && trustedCertificate.getTrustSunsetDate() != null) {
			controlTime = trustedCertificate.getTrustSunsetDate();
			item = firstItem = sunsetDateCheck(trustedCertificate);

		} else {
			controlTime = currentTime;
		}

		List<CertificateWrapper> certificateChain = token.getCertificateChain();
		if (Utils.isCollectionNotEmpty(certificateChain)) {

			certificateChain = reduceChainUntilFirstTrustAnchor(certificateChain);

			/*
			 * 2) For each certificate in the chain starting from the first
			 * certificate (the certificate issued by the trust anchor):
			 */
			certificateChain = Utils.reverseList(certificateChain); // trust anchor -> ... -> signing-certificate

			for (CertificateWrapper certificate : certificateChain) {
				if (isTrustAnchor(certificate)) {
					// skip for trust anchor
					continue;
				}

				/*
				 * a) The building block shall select revocation status information from
				 * the certificate validation data provided satisfying the following:
				 * 
				 * - the revocation status information is consistent with the rules conditioning its use
				 *   to check the revocation status of the considered certificate. In the case of a CRL,
				 *   it shall satisfy the checks specified in IETF RFC 5280 [1], clause 6.3.3 (b) to (l);
				 *   with the exception of the verification if the control-time is within the validity period
				 *   of the certificate of the issuer of the CRL; and
				 *
				 * - the issuance date of the revocation status information is before control time; and
				 *
				 * - the set of POEs contains a proof of existence of the certificate and
				 *   the revocation status information at (or before) control time.
				 * 
				 * If at least one revocation status information is selected,
				 * the building block shall go to the next step.
				 * If there is no such information, the building block shall return
				 * the indication INDETERMINATE with the sub indication NO_POE.
				 */

				CertificateRevocationWrapper latestCompliantRevocation = null;

				final SubContext subContext = getSubContext(certificate);
				RevocationDataRequiredCheck<XmlVTS> revocationDataRequiredCheck = revocationDataRequired(certificate, subContext);
				boolean revocationDataRequired = revocationDataRequiredCheck.process();
				if (revocationDataRequired) {
					final LevelRule revocationIssuerSunsetDateConstraint = policy.getCertificateSunsetDateConstraint(
							Context.REVOCATION, SubContext.SIGNING_CERT);
					final List<CertificateRevocationWrapper> certificateRevocationData = SubContext.SIGNING_CERT.equals(subContext) ?
							ValidationProcessUtils.getAcceptableRevocationDataForPSVIfExistOrReturnAll(
									token, certificate, currentTime, bbbs, poe, revocationIssuerSunsetDateConstraint) :
							certificate.getCertificateRevocationData();

					CertificateRevocationSelector certificateRevocationSelector = new ValidationTimeSlidingCertificateRevocationSelector(
							i18nProvider, certificate, certificateRevocationData, controlTime, bbbs, tokenBBB.getId(), poe, policy);
					XmlCRS xmlCRS = certificateRevocationSelector.execute();
					result.getCRS().add(xmlCRS);

					ChainItem<XmlVTS> satisfyingRevocationDataExists = satisfyingRevocationDataExists(xmlCRS, certificate, controlTime);
					if (item == null) {
						item = firstItem = satisfyingRevocationDataExists;
					} else {
						item = item.setNextItem(satisfyingRevocationDataExists);
					}

					latestCompliantRevocation = certificateRevocationSelector.getLatestAcceptableCertificateRevocation();

				} else {
					if (item == null) {
						item = firstItem = revocationDataRequiredCheck;
					} else {
						item = item.setNextItem(revocationDataRequiredCheck);
					}
				}

				if (latestCompliantRevocation == null) {
					// skip revocation checks
				}
				/*
				 * b) If the certificate is marked as revoked in any of the revocation status information
				 * found in the previous step, the building block shall perform the following steps:
				 *
				 * - select the revocation status information that has been issued the latest;
				 *
				 * - set control time to the revocation time whenever the validation policy requires
				 *   to use the shell model; or, when the validation policy requires to use the chain model and
				 *   the revocation reason is key compromise or unknown.
				 *
				 * - go to step d).
				 */
				else if (latestCompliantRevocation.isRevoked()) {
					ValidationModel validationModel = policy.getValidationModel();
					RevocationReason revocationReason = latestCompliantRevocation.getReason();
					// NOTE : HYBRID model is treated as CHAIN for Signing Cert and as SHELL for CAs
					if (ValidationModel.SHELL.equals(validationModel)
							|| (ValidationModel.HYBRID.equals(validationModel) && SubContext.CA_CERTIFICATE.equals(subContext))
							|| RevocationReason.KEY_COMPROMISE.equals(revocationReason) || RevocationReason.UNSPECIFIED.equals(revocationReason)) {
						controlTime = latestCompliantRevocation.getRevocationDate();
					}
				}
				/*
				 * c) If the certificate is not marked as revoked in all of the revocation data found in step a),
				 * the building block shall select the revocation data that has been issued the latest,
				 * run the Revocation Freshness Checker with that revocation data, the certificate for which
				 * the revocation status is being checked and the control time. If it returns FAILED,
				 * the building block shall set control time to the time that is the earliest between time
				 * A and time B, where time A is the current value of control time and time B is
				 * the issuance time of the revocation status information contained within the revocation data.
				 * Otherwise, the building block shall not change the value of control time.
				 */
				else {
					RevocationFreshnessChecker rfc = new RevocationFreshnessChecker(
							i18nProvider, latestCompliantRevocation, controlTime, context, subContext, policy);
					XmlRFC execute = rfc.execute();
					if (execute.getConclusion() != null && Indication.FAILED.equals(execute.getConclusion().getIndication())) {
						Date thisUpdate = latestCompliantRevocation.getThisUpdate();
						if (thisUpdate.before(controlTime)) {
							controlTime = thisUpdate;
						}
					}
				}

				/*
				 * d) The building block shall apply the cryptographic constraints to the certificate and
				 * the revocation status information against the control time. If the certificate
				 * (or the revocation status information) does not match these constraints, the building block shall
				 * set control time to the latest time up to which the listed algorithms were all considered reliable.
				 */
                Date cryptoNotAfterDate = null;
                
                XmlAOV certificateAOV = getCertificateAlgorithmObsolescenceResult(certificate, controlTime, subContext);
				if (!isValidConclusion(certificateAOV.getConclusion())) {
					XmlCryptographicValidation cryptographicValidation = ValidationProcessUtils.getFailCryptographicValidation(certificateAOV);
					cryptoNotAfterDate = cryptographicValidation != null ? cryptographicValidation.getNotAfter() : null;
				}

				if (latestCompliantRevocation != null) {
					XmlAOV revocationAOV = getRevocationDataAlgorithmObsolescenceResult(latestCompliantRevocation, controlTime);
					if (!isValidConclusion(revocationAOV.getConclusion())) {
						XmlCryptographicValidation cryptographicValidation = ValidationProcessUtils.getFailCryptographicValidation(revocationAOV);
						Date revCryptoNotAfter = cryptographicValidation != null ? cryptographicValidation.getNotAfter() : null;
						if (cryptoNotAfterDate == null ||
								(revCryptoNotAfter != null && revCryptoNotAfter.before(cryptoNotAfterDate))) {
							cryptoNotAfterDate = revCryptoNotAfter;
						}
					}
				}
                
                if (cryptoNotAfterDate != null && cryptoNotAfterDate.before(controlTime)) {
                    controlTime = cryptoNotAfterDate;
                }

                /*
                 * e) The building block shall continue with the next certificate in the chain or,
                 * if no further certificate exists, the building block shall return the status
                 * indication PASSED and the calculated control time.
                 */

			}
		}

		ChainItem<XmlVTS> controlTimeConclusiveCheck = controlTimeConclusive(controlTime);
		if (item == null) {
			item = firstItem = controlTimeConclusiveCheck;
		} else {
			item = item.setNextItem(controlTimeConclusiveCheck);
		}
	}

	@Override
	protected void addAdditionalInfo() {
		result.setControlTime(controlTime);
		result.setTrustAnchor(trustedCertificate.getId());
	}

	private SubContext getSubContext(CertificateWrapper certificate) {
		return token.getSigningCertificate().getId().equals(certificate.getId()) ? SubContext.SIGNING_CERT : SubContext.CA_CERTIFICATE;
	}

	private List<CertificateWrapper> reduceChainUntilFirstTrustAnchor(List<CertificateWrapper> originalCertificateChain) {
		List<CertificateWrapper> result = new ArrayList<>();
		for (CertificateWrapper cert : originalCertificateChain) {
			result.add(cert);
			if (isTrustAnchor(cert)) {
				break;
			}
		}
		return result;
	}

	private boolean isTrustAnchor(CertificateWrapper certificate) {
		return certificate.equals(trustedCertificate);
	}

	private ChainItem<XmlVTS> sunsetDateCheck(CertificateWrapper trustedCertificate) {
		return new SunsetDateCheck(i18nProvider, result, trustedCertificate, getFailLevelRule());
	}

	private RevocationDataRequiredCheck<XmlVTS> revocationDataRequired(CertificateWrapper certificate, SubContext subContext) {
		CertificateApplicabilityRule constraint = policy.getRevocationDataSkipConstraint(context, subContext);
		LevelRule sunsetDateConstraint = policy.getCertificateSunsetDateConstraint(context, subContext);
		return new RevocationDataRequiredCheck<>(i18nProvider, result, certificate, currentTime, sunsetDateConstraint, constraint);
	}

	private ChainItem<XmlVTS> satisfyingRevocationDataExists(XmlCRS crsResult, CertificateWrapper certificateWrapper,
															 Date controlTime) {
		return new SatisfyingRevocationDataExistsCheck<>(i18nProvider, result, crsResult, certificateWrapper,
				controlTime, getFailLevelRule());
	}

	private ChainItem<XmlVTS> controlTimeConclusive(Date controlTime) {
		return new ControlTimeCheck(i18nProvider, result, controlTime, getFailLevelRule());
	}
	
    private XmlAOV getCertificateAlgorithmObsolescenceResult(CertificateWrapper certificateWrapper, Date controlTime, SubContext subContext) {
		CertificateAlgorithmObsolescenceValidation aov = new CertificateAlgorithmObsolescenceValidation(
				i18nProvider, certificateWrapper, context, subContext, controlTime, policy);
        return aov.execute();
    }
    
    private XmlAOV getRevocationDataAlgorithmObsolescenceResult(RevocationWrapper revocationWrapper, Date controlTime) {
		RevocationDataAlgorithmObsolescenceValidation aov = new RevocationDataAlgorithmObsolescenceValidation(
				i18nProvider, revocationWrapper, controlTime, policy);
		return aov.execute();
    }

}
