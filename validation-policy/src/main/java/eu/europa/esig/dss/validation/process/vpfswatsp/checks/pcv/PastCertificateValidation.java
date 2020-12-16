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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.pcv;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
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
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.pcv.checks.ValidationTimeSlidingCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.ValidationTimeSliding;

import java.util.Date;
import java.util.List;

/**
 * Validates certificate in a past
 */
public class PastCertificateValidation extends Chain<XmlPCV> {

	/** Token to be validated */
	private final TokenProxy token;

	/** The related BBBs */
	private final XmlBasicBuildingBlocks bbb;

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
	 * @param bbb {@link XmlBasicBuildingBlocks}
	 * @param poe {@link POEExtraction}
	 * @param currentTime {@link Date}
	 * @param policy {@link ValidationPolicy}
	 * @param context {@link Context}
	 */
	public PastCertificateValidation(I18nProvider i18nProvider, TokenProxy token, XmlBasicBuildingBlocks bbb, 
			POEExtraction poe, Date currentTime, ValidationPolicy policy, Context context) {
		super(i18nProvider, new XmlPCV());

		this.token = token;
		this.bbb = bbb;
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
		 * 9.2.1.4 Processing The following steps shall be performed: 1) Build a
		 * new prospective certificate chain that has not yet been evaluated.
		 * The chain shall satisfy the conditions of a prospective certificate
		 * chain as stated in [4], clause 6.1, using one of the trust anchors
		 * provided in the inputs: a) If no new chain can be built, abort the
		 * processing with the current status and the last chain built or, if no
		 * chain was built, with INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND. b)
		 * Otherwise, go to the next step.
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
		 * the validity of the signer's certificate. The validation shall not include 
		 * revocation checking:
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
		 * 3) The building block shall perform the validation time sliding
		 * process as per clause 5.6.2.2 with the following inputs: the
		 * prospective chain, the set of POEs and the cryptographic constraints.
		 * If it outputs a success indication, the building block shall go to
		 * the next step. Otherwise, the building block shall set the current
		 * status to the returned indication and sub-indication and shall go
		 * back to step 1.
		 */
		
		item = item.setNextItem(validationTimeSliding());

		/*
		 * 4) The building block shall apply the chain constraints to the chain.
		 * If the chain does not match these constraints, the building block
		 * shall set the current status to FAILED/CHAIN_CONSTRAINTS_FAILURE and
		 * shall go to step 1.
		 */
		if (controlTime != null) {
			List<CertificateWrapper> certificateChain = token.getCertificateChain();
			for (CertificateWrapper certificate : certificateChain) {
				if (certificate.isTrusted()) {
					// There is not need to check for the trusted certificate
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
		 * 5) The building block shall return the current status . If the
		 * current status is PASSED, the building block shall also return the
		 * certificate chain as well as the calculated validation time returned
		 * in step 3.
		 */
	}

	private ChainItem<XmlPCV> prospectiveCertificateChain() {
		LevelConstraint constraint = policy.getProspectiveCertificateChainConstraint(context);
		return new ProspectiveCertificateChainCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlPCV> validationTimeSliding() {
		ValidationTimeSliding validationTimeSliding = 
				new ValidationTimeSliding(i18nProvider, token, currentTime, poe, bbb, context, policy);
		
		XmlVTS vts = validationTimeSliding.execute();
		bbb.setVTS(vts);
		if (isValid(vts)) {
			controlTime = vts.getControlTime();
		}

		return new ValidationTimeSlidingCheck(i18nProvider, result, vts, token.getId(), getFailLevelConstraint());
	}

	private ChainItem<XmlPCV> cryptographicCheck(XmlPCV result, CertificateWrapper certificate, Date validationTime, SubContext subContext) {
		CryptographicConstraint constraint = policy.getCertificateCryptographicConstraint(context, subContext);
		MessageTag position = ValidationProcessUtils.getCertificateChainCryptoPosition(context);
		
		return new CryptographicCheck<>(i18nProvider, result, certificate, position, validationTime, constraint);
	}

	@Override
	protected void addAdditionalInfo() {
		result.setControlTime(controlTime); // can be null
	}

}
