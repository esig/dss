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
package eu.europa.esig.dss.validation.process.bbb.xcv;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.SubContext;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.Model;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.CheckSubXCVResult;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.ProspectiveCertificateChainCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.TrustServiceStatusCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.TrustServiceTypeIdentifierCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.SubX509CertificateValidation;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.CertificateValidationBeforeSunsetDateCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.ProspectiveCertificateChainAtValidationTimeCheck;

import java.util.Date;
import java.util.Iterator;
import java.util.List;

/**
 * 5.2.6 X.509 certificate validation
 * 
 * This building block validates the signing certificate at current time.
 */
public class X509CertificateValidation extends Chain<XmlXCV> {

	/** The certificate to be validated */
	private final CertificateWrapper currentCertificate;

	/** The validation time */
	private final Date currentTime;

	/** The certificate usage time */
	private final Date usageTime;

	/** The validation context */
	private final Context context;

	/** The validation policy */
	private final ValidationPolicy validationPolicy;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param currentCertificate {@link CertificateWrapper} to validate
	 * @param currentTime {@link Date}
	 * @param context {@link Context}
	 * @param validationPolicy {@link ValidationPolicy}
	 */
	public X509CertificateValidation(I18nProvider i18nProvider, CertificateWrapper currentCertificate,
									 Date currentTime, Context context, ValidationPolicy validationPolicy) {
		this(i18nProvider, currentCertificate, currentTime, currentTime, context, validationPolicy);
	}

	/**
	 * Default constructor with usage time
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param currentCertificate {@link CertificateWrapper} to validate
	 * @param currentTime {@link Date}
	 * @param usageTime {@link Date}
	 * @param context {@link Context}
	 * @param validationPolicy {@link ValidationPolicy}
	 */
	public X509CertificateValidation(I18nProvider i18nProvider, CertificateWrapper currentCertificate,
									 Date currentTime, Date usageTime, Context context, ValidationPolicy validationPolicy) {
		super(i18nProvider, new XmlXCV());

		this.currentCertificate = currentCertificate;
		this.currentTime = currentTime;
		this.usageTime = usageTime;

		this.context = context;
		this.validationPolicy = validationPolicy;
	}
    
	@Override
	protected MessageTag getTitle() {
		return MessageTag.X509_CERTIFICATE_VALIDATION;
	}

	@Override
	protected void initChain() {

		/*
		 * 1) If the signing certificate represents a trust anchor, then:
		 *
		 * a) If, in the X.509 Validation Constraints, a sunset date is associated to that trust anchor,
		 *    the building block shall check whether validation is before the sunset date. If validation time is
		 *    at or after the sunset date, the building block shall set the current status to
		 *    INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND_NO_POE and shall go to step 2).
		 * b) Else, the building block may, based on signature policy or local configuration, return with
		 *    the indication PASSED. Otherwise, the building block shall go to the next step.
		 *
		 * 2) The building block shall build a new prospective certificate chain that has not yet been evaluated.
		 * If the "Other Certificates" parameter is present, only certificates contained in that set of certificates
		 * may be used to build the chain. The chain shall satisfy the conditions of a prospective certificate chain:
		 *
		 * a) If no new chain can be built, the building block shall return the current status, the last chain built
		 *    and any additional information saved in step 4-a) or, if no chain has been built, the indication
		 *    INDETERMINATE with the sub-indication NO_CERTIFICATE_CHAIN_FOUND.
		 * b) Otherwise, the building block shall add this chain to the set of prospected chains and shall go to step 3).
		 *
		 * 3) If, in the X.509 Validation Constraints, a sunset date is associated to the trust anchor from which
		 * the current chain has been built, the building block shall check whether validation is before
		 * the sunset date. If validation time is at or after the sunset date, the building block shall set
		 * the current status to INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND_NO_POE and shall go to step 2).
		 */
		ChainItem<XmlXCV> item = firstItem = prospectiveCertificateChain();

		CertificateWrapper trustAnchorCandidate = currentCertificate;
		List<CertificateWrapper> certificateChain = currentCertificate.getCertificateChain();
		SubContext subContext = SubContext.SIGNING_CERT;
		Iterator<CertificateWrapper> certChainIt = Utils.isCollectionNotEmpty(certificateChain) ? certificateChain.iterator() : null;

		CertificateWrapper trustAnchor = null;

		do {
			if (trustAnchorCandidate.isTrusted() && trustAnchorCandidate.getTrustStartDate() != null || trustAnchorCandidate.getTrustSunsetDate() != null) {

				item = item.setNextItem(validationBeforeSunsetDate(trustAnchorCandidate, subContext, currentTime));

			}

			if (isTrustAnchorReached(trustAnchorCandidate, subContext)) {

				item = item.setNextItem(prospectiveCertificateChainValidAtValidationTime(trustAnchorCandidate, subContext, currentTime));

				trustAnchor = trustAnchorCandidate;
				break;
			}

			if (certChainIt != null && certChainIt.hasNext()) {
				trustAnchorCandidate = certChainIt.next();
			} else {
				trustAnchorCandidate = null;
			}
			subContext = SubContext.CA_CERTIFICATE;

		} while (trustAnchorCandidate != null);

		/*
		 * 4) The building block shall perform validation of the prospective certificate chain with the following inputs:
		 * the prospective chain built in the previous step, the trust anchor used in the previous step, the X.509 parameters
		 * provided in the inputs and the validation time. The validation shall be following the PKIX Certification Path
		 * Validation of IETF RFC 5280 [1], clause 6.1 with the exception of the validity model and the verification of
		 * whether the validation time is during the validity period of the signing certificate.
	     */
		if (currentCertificate.isTrusted() || currentCertificate.isTrustedChain() || !prospectiveCertificateChainCheckEnforced()) {

			item = item.setNextItem(trustServiceWithExpectedTypeIdentifier());

			item = item.setNextItem(trustServiceWithExpectedStatus());

			SubX509CertificateValidation certificateValidation = new SubX509CertificateValidation(i18nProvider,
					currentCertificate, currentTime, currentTime, context, SubContext.SIGNING_CERT, validationPolicy);
			XmlSubXCV subXCV = certificateValidation.execute();
			result.getSubXCV().add(subXCV);

			item = item.setNextItem(checkSubXCVResult(subXCV));

			if (trustAnchor != null && trustAnchor == currentCertificate) {
				return;
			}

			final Model model = validationPolicy.getValidationModel();

			// Check CA_CERTIFICATEs
			Date lastDate = Model.SHELL.equals(model) ? currentTime : currentCertificate.getNotBefore();
			if (Utils.isCollectionNotEmpty(certificateChain)) {
				for (CertificateWrapper certificate : certificateChain) {
					certificateValidation = new SubX509CertificateValidation(i18nProvider,
							certificate, lastDate, currentTime, context, SubContext.CA_CERTIFICATE, validationPolicy);
					subXCV = certificateValidation.execute();
					result.getSubXCV().add(subXCV);

					item = item.setNextItem(checkSubXCVResult(subXCV));

					lastDate = Model.HYBRID.equals(model) ? lastDate : (Model.SHELL.equals(model) ? currentTime : certificate.getNotBefore());

					if (trustAnchor != null && trustAnchor == certificate) {
						return;
					}
				}
			}

		}
	}

	private ChainItem<XmlXCV> prospectiveCertificateChain() {
		LevelConstraint constraint = validationPolicy.getProspectiveCertificateChainConstraint(context);
		return new ProspectiveCertificateChainCheck<>(i18nProvider, result, currentCertificate, context, constraint);
	}

	private ChainItem<XmlXCV> validationBeforeSunsetDate(CertificateWrapper certificate, SubContext subContext, Date validationTime) {
		LevelConstraint constraint = validationPolicy.getCertificateSunsetDateConstraint(context, subContext);
		return new CertificateValidationBeforeSunsetDateCheck<>(i18nProvider, result, certificate, validationTime,
				ValidationProcessUtils.getConstraintOrMaxLevel(constraint, Level.WARN));
	}

	private ChainItem<XmlXCV> prospectiveCertificateChainValidAtValidationTime(CertificateWrapper certificate, SubContext subContext, Date validationTime) {
		LevelConstraint constraint = validationPolicy.getCertificateSunsetDateConstraint(context, subContext);
		return new ProspectiveCertificateChainAtValidationTimeCheck(i18nProvider, result, certificate, validationTime, constraint);
	}

	private ChainItem<XmlXCV> trustServiceWithExpectedTypeIdentifier() {
		MultiValuesConstraint constraint = validationPolicy.getTrustServiceTypeIdentifierConstraint(context);
		return new TrustServiceTypeIdentifierCheck(i18nProvider, result, currentCertificate, usageTime, context, constraint);
	}

	private ChainItem<XmlXCV> trustServiceWithExpectedStatus() {
		MultiValuesConstraint constraint = validationPolicy.getTrustServiceStatusConstraint(context);
		return new TrustServiceStatusCheck(i18nProvider, result, currentCertificate, usageTime, context, constraint);
	}

	private ChainItem<XmlXCV> checkSubXCVResult(XmlSubXCV subXCVResult) {
		return new CheckSubXCVResult(i18nProvider, result, subXCVResult, getFailLevelConstraint());
	}

	private boolean prospectiveCertificateChainCheckEnforced() {
		LevelConstraint constraint = validationPolicy.getProspectiveCertificateChainConstraint(context);
		return constraint != null && Level.FAIL == constraint.getLevel();
	}

	private boolean isTrustAnchor(CertificateWrapper certificateWrapper, Context context, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateSunsetDateConstraint(context, subContext);
		return ValidationProcessUtils.isTrustAnchor(certificateWrapper, currentTime, constraint);
	}

	private boolean isTrustAnchorReached(CertificateWrapper certificateWrapper, SubContext subContext) {
		return isTrustAnchor(certificateWrapper, context, subContext)
				|| (certificateWrapper.isTrusted() && !certificateWrapper.isTrustedChain()); // second part is to filter only prospective certificate chains
	}

	@Override
	protected void collectMessages(XmlConclusion conclusion, XmlConstraint constraint) {
		// collect all messages, except prospective certificate chain expiration warning (only final message should be returned)
		if (!XmlBlockType.SUB_XCV_TA.equals(constraint.getBlockType())) {
			super.collectMessages(conclusion, constraint);
		}
	}

	@Override
	protected void collectAdditionalMessages(XmlConclusion conclusion) {
		for (XmlSubXCV subXCV : result.getSubXCV()) {
			collectAllMessages(conclusion, subXCV.getConclusion());
			for (XmlConstraint constraint : subXCV.getConstraint()) {
				if (XmlBlockType.SUB_XCV_TA.equals(constraint.getBlockType())) {
					if (constraint.getError() != null) {
						removeMessage(conclusion.getErrors(), constraint.getError().getKey());
					}
					if (constraint.getWarning() != null) {
						removeMessage(conclusion.getWarnings(), constraint.getWarning().getKey());
					}
					if (constraint.getInfo() != null) {
						removeMessage(conclusion.getInfos(), constraint.getInfo().getKey());
					}
				}
			}
		}
	}
	
	private void removeMessage(List<XmlMessage> messages, String messageKey) {
		if (Utils.isCollectionEmpty(messages)) {
			return;
		}
        messages.removeIf(xmlMessage -> messageKey.equals(xmlMessage.getKey()));
	}

}
