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

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
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
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.CheckSubXCVResult;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.ProspectiveCertificateChainCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.TrustServiceStatusCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.TrustServiceTypeIdentifierCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.SubX509CertificateValidation;

import java.util.Date;
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

		ChainItem<XmlXCV> item = firstItem = prospectiveCertificateChain();

		if (currentCertificate.isTrusted() || currentCertificate.isTrustedChain() || !prospectiveCertificateChainCheckEnforced()) {

			item = item.setNextItem(trustServiceWithExpectedTypeIdentifier());

			item = item.setNextItem(trustServiceWithExpectedStatus());

			SubX509CertificateValidation certificateValidation = new SubX509CertificateValidation(i18nProvider,
					currentCertificate, currentTime, currentTime, context, SubContext.SIGNING_CERT, validationPolicy);
			XmlSubXCV subXCV = certificateValidation.execute();
			result.getSubXCV().add(subXCV);

			item = item.setNextItem(checkSubXCVResult(subXCV));

			boolean trustAnchorReached = currentCertificate.isTrusted();

			final Model model = validationPolicy.getValidationModel();

			// Check CA_CERTIFICATEs
			Date lastDate = Model.SHELL.equals(model) ? currentTime : currentCertificate.getNotBefore();
			List<CertificateWrapper> certificateChainList = currentCertificate.getCertificateChain();
			if (Utils.isCollectionNotEmpty(certificateChainList)) {
				for (CertificateWrapper certificate : certificateChainList) {
					if (!trustAnchorReached) {
						certificateValidation = new SubX509CertificateValidation(i18nProvider,
								certificate, lastDate, currentTime, context, SubContext.CA_CERTIFICATE, validationPolicy);
						subXCV = certificateValidation.execute();
						result.getSubXCV().add(subXCV);

						item = item.setNextItem(checkSubXCVResult(subXCV));

						trustAnchorReached = certificate.isTrusted();
						lastDate = Model.HYBRID.equals(model) ? lastDate : (Model.SHELL.equals(model) ? currentTime : certificate.getNotBefore());
					}
				}
			}

		}
	}

	private ChainItem<XmlXCV> prospectiveCertificateChain() {
		LevelConstraint constraint = validationPolicy.getProspectiveCertificateChainConstraint(context);
		return new ProspectiveCertificateChainCheck<>(i18nProvider, result, currentCertificate, context, constraint);
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

	@Override
	protected void collectAdditionalMessages(XmlConclusion conclusion) {
		for (XmlSubXCV subXCV : result.getSubXCV()) {
			collectAllMessages(conclusion, subXCV.getConclusion());
		}
	}
	
}
