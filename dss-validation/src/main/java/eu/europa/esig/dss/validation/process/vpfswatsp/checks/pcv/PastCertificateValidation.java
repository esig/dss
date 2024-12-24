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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.pcv;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVTS;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Context;
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
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.pcv.checks.ProspectiveCertificateChainCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.pcv.checks.SuccessfulValidationTimeSlidingFoundCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.pcv.checks.ValidationTimeSlidingCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.ValidationTimeSliding;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Validates certificate in a past
 */
public class PastCertificateValidation extends Chain<XmlPCV> {

	/** Token to be validated */
	private final TokenProxy token;

	/** Map of all BBBs */
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	/** POE container */
	private final POEExtraction poe;

	/** Validation time */
	private final Date currentTime;

	/** Validation policy */
	private final ValidationPolicy policy;

	/** Validation context */
	private final Context context;

	/** The control time */
	private Date controlTime;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param token {@link TokenProxy}
	 * @param bbbs map of all {@link XmlBasicBuildingBlocks}
	 * @param poe {@link POEExtraction}
	 * @param currentTime {@link Date}
	 * @param policy {@link ValidationPolicy}
	 * @param context {@link Context}
	 */
	public PastCertificateValidation(I18nProvider i18nProvider, TokenProxy token, Map<String, XmlBasicBuildingBlocks> bbbs,
			POEExtraction poe, Date currentTime, ValidationPolicy policy, Context context) {
		super(i18nProvider, new XmlPCV());

		this.token = token;
		this.bbbs = bbbs;
		this.poe = poe;
		this.currentTime = currentTime;

		this.policy = policy;
		this.context = context;
	}
    
	@Override
	protected MessageTag getTitle() {
		return MessageTag.PAST_CERTIFICATE_VALIDATION;
	}

	@Override
	protected void initChain() {

		CertificateWrapper signingCertificate = token.getSigningCertificate();

		/*
		 * 1) The building block shall build a new prospective certificate chain that
		 * has not yet been evaluated:
		 * a) If no new chain can be built, the building block shall return the current
		 *    status and the last chain built or, if no chain was built, the indication
		 *    INDETERMINATE with the sub-indication NO_CERTIFICATE_CHAIN_FOUND.
		 * b) Otherwise, the building block shall go to the next ste
		 */
		ChainItem<XmlPCV> item = firstItem = prospectiveCertificateChain();

		/*
		 * 2) The building block shall run the Certification Path Validation of 
		 * IETF RFC 5280 [1], clause 6.1, with the following inputs: the prospective 
		 * certificate chain built in the previous step, the trust anchor used in the
		 * previous step, the X.509 parameters provided in the inputs and either:
		 * 
		 * i) when the validation policy requires to use the shell model, a date from 
		 * the intersection of the validity intervals of all the certificates in the 
		 * prospective certificate chain; or
		 * 
		 * ii) when the validation policy requires to use the chain model, a date from
		 * the validity of the signer's certificate.
		 *
		 * The validation shall not include revocation checking nor verifying that current
		 * time is before a trust anchor sunset date when the X.509 validation constraints
		 * define such a sunset date:
		 * 
		 * a) If the certificate path validation returns PASSED, the building block 
		 * shall go to the next step.
		 * 
		 * b) If the certificate path validation returns a failure indication, the building 
		 * block shall set the current status to 
		 * INDETERMINATE/CERTIFICATE_CHAIN_GENERAL_FAILURE and shall go to step 1. 
		 */
		
		// Certificates are validated before (see (Sub)X509CertificateValidation)
		
		// TODO : process different validation models (?)

		/*
		 * 3) The building block shall perform the validation time sliding process as per
		 * clause 5.6.2.2 with the following inputs: the prospective chain, the set of POEs,
		 * the set of certificate validation data, the sunset date of the trust anchor from
		 * which the current chain has been built when the X.509 validation constraint specify
		 * such a date, and the cryptographic constraints. If it outputs a success indication,
		 * the building block shall go to the next step. Otherwise, the building block shall
		 * set the current status to the returned indication and sub-indication and shall go
		 * back to step 1).
		 */

		CertificateWrapper trustedCertificate = null;

		final List<XmlVTS> vtsList = new ArrayList<>();
		for (CertificateWrapper certificateWrapper : token.getCertificateChain()) {
			if (certificateWrapper.isTrusted()) {
				trustedCertificate = certificateWrapper;
				XmlVTS vts = getVTSResult(trustedCertificate);
				vtsList.add(vts);

				item = item.setNextItem(validationTimeSliding(vts, trustedCertificate));

				if (trustedCertificate.isSelfSigned()
						|| trustedCertificate.getTrustSunsetDate() == null || !trustedCertificate.isTrustedChain()) {
					// no sunset date change -> no reason to restart VTS
					break;
				}
			}
		}

		XmlVTS vts = getBestValidationTimeSliding(vtsList);
		if (vts != null) {
			XmlBasicBuildingBlocks bbb = bbbs.get(token.getId());
			bbb.setVTS(vts);
			if (isValid(vts)) {
				controlTime = vts.getControlTime();
			}
		}

		item = item.setNextItem(successfulValidationTimeSlidingFound(vts));

		/*
		 * 4) The building block shall apply the X.509 validation constraints to the chain.
		 * If the chain does not match these constraints, the building block shall set the
		 * current status to INDETERMINATE/CHAIN_CONSTRAINTS_FAILURE and shall go to step 1).
		 */
		if (controlTime != null) {
			List<CertificateWrapper> certificateChain = token.getCertificateChain();
			for (CertificateWrapper certificate : certificateChain) {
				if (trustedCertificate == certificate) {
					// There is no need to check for the trusted certificate
					break;
				}

				SubContext subContext = SubContext.CA_CERTIFICATE;
				if (Utils.areStringsEqual(signingCertificate.getId(), certificate.getId())) {
					subContext = SubContext.SIGNING_CERT;
				}

				item = item.setNextItem(cryptographicCheck(result, certificate, controlTime, subContext));
			}

		}

		/*
		 * 5) The building block shall return the current status. If the
		 * current status is PASSED, the building block shall also return the
		 * certificate chain as well as the calculated validation time returned
		 * in step 3.
		 */
	}

	private ChainItem<XmlPCV> prospectiveCertificateChain() {
		LevelConstraint constraint = policy.getProspectiveCertificateChainConstraint(context);
		return new ProspectiveCertificateChainCheck(i18nProvider, result, token, constraint);
	}

	private XmlVTS getVTSResult(CertificateWrapper trustedCertificate) {
		ValidationTimeSliding validationTimeSliding =
				new ValidationTimeSliding(i18nProvider, token, trustedCertificate, currentTime, poe, bbbs, context, policy);
		return validationTimeSliding.execute();
	}

	private ChainItem<XmlPCV> validationTimeSliding(XmlVTS vts, CertificateWrapper trustedCertificate) {
		return new ValidationTimeSlidingCheck(i18nProvider, result, vts, token.getId(), trustedCertificate, getWarnLevelConstraint());
	}

	private ChainItem<XmlPCV> successfulValidationTimeSlidingFound(XmlVTS vts) {
		return new SuccessfulValidationTimeSlidingFoundCheck(i18nProvider, result, vts, getFailLevelConstraint());
	}

	private ChainItem<XmlPCV> cryptographicCheck(XmlPCV result, CertificateWrapper certificate, Date validationTime, SubContext subContext) {
		CryptographicConstraint constraint = policy.getCertificateCryptographicConstraint(context, subContext);
		MessageTag position = ValidationProcessUtils.getCertificateChainCryptoPosition(context);
		
		return new CryptographicCheck<>(i18nProvider, result, certificate, position, validationTime, constraint);
	}

	/**
	 * This method returns a successful VTS result with the latest control time
	 * (enough to proof validity of the signature), when applicable
	 *
	 * @param vtsList a list of {@link XmlVTS}
	 * @return {@link XmlVTS}
	 */
	private XmlVTS getBestValidationTimeSliding(List<XmlVTS> vtsList) {
		if (Utils.isCollectionEmpty(vtsList)) {
			return null;
		}
		XmlVTS bestVTS = null;
		for (XmlVTS xmlVTS : vtsList) {
			if (bestVTS == null || (!isValid(bestVTS) && (isValid(xmlVTS) || bestVTS.getControlTime().before(xmlVTS.getControlTime())) ||
					(isValid(xmlVTS) && bestVTS.getControlTime().before(xmlVTS.getControlTime())))) {
				bestVTS = xmlVTS;
			}
		}
		return bestVTS;
	}

	@Override
	protected void addAdditionalInfo() {
		result.setControlTime(controlTime); // can be null
	}

	@Override
	protected void collectMessages(XmlConclusion conclusion, XmlConstraint constraint) {
		if (XmlBlockType.VTS.equals(constraint.getBlockType())) {
			// skip validation for VTS
		} else {
			super.collectMessages(conclusion, constraint);
		}
	}

}
