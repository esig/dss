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

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVTS;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.policy.SubContext;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.BasicBuildingBlockDefinition;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateSignatureValidCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.pcv.checks.ProspectiveCertificateChainCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.pcv.checks.ValidationTimeSlidingCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.ValidationTimeSliding;

public class PastCertificateValidation extends Chain<XmlPCV> {

	private final TokenProxy token;
	private final DiagnosticData diagnosticData;
	private final XmlBasicBuildingBlocks bbb;
	private final POEExtraction poe;

	private final Date currentTime;
	private final ValidationPolicy policy;
	private final Context context;
	private Date controlTime;

	public PastCertificateValidation(TokenProxy token, DiagnosticData diagnosticData, XmlBasicBuildingBlocks bbb, POEExtraction poe, Date currentTime,
			ValidationPolicy policy, Context context) {
		super(new XmlPCV());
		result.setTitle(BasicBuildingBlockDefinition.PAST_CERTIFICATE_VALIDATION.getTitle());

		this.token = token;
		this.diagnosticData = diagnosticData;
		this.bbb = bbb;
		this.poe = poe;
		this.currentTime = currentTime;

		this.policy = policy;
		this.context = context;
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
		 * IETF RFC 5280 [1], clause 6.1, with the following inputs: the
		 * prospective chain built in the previous step, the trust anchor used
		 * in the previous step, the X.509 parameters provided in the inputs and
		 * a date from the intersection of the validity intervals of all the
		 * certificates in the prospective chain. The validation shall not
		 * include revocation checking for the signing certificate: a) If the
		 * certificate path validation returns PASSED, the building block shall
		 * go to the next step. b) If the certificate path validation returns a
		 * failure indication because an intermediate CA has been determined to
		 * be revoked, the building block shall set the current status to
		 * INDETERMINATE/REVOKED_CA_NO_POE and shall go to step 1. c) If the
		 * certificate path validation returns a failure indication with any
		 * other reason, the building block shall set the current status to
		 * INDETERMINATE/CERTIFICATE_CHAIN_GENERAL_FAILURE and shall go to step
		 * 1. Or d) If the certificate path validation returns any other failure
		 * indication, the building block shall go to step 1.
		 * 
		 * ==> Simplified because DSS only uses one certificate chain
		 */

		Date intervalNotBefore = null;
		Date intervalNotAfter = null;

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

			if (intervalNotBefore == null || intervalNotBefore.before(certificate.getNotBefore())) {
				intervalNotBefore = certificate.getNotBefore();
			}
			if (intervalNotAfter == null || intervalNotAfter.after(certificate.getNotAfter())) {
				intervalNotAfter = certificate.getNotAfter();
			}

			if (SubContext.CA_CERTIFICATE.equals(subContext)) {
				CertificateRevocationWrapper latestRevocation = diagnosticData.getLatestRevocationDataForCertificate(certificate);
				if (latestRevocation != null && latestRevocation.isRevoked()) {
					Date caRevocationDate = latestRevocation.getRevocationDate();
					if (caRevocationDate != null && intervalNotAfter.after(caRevocationDate)) {
						intervalNotAfter = caRevocationDate;
					}
				}

				// TODO REVOKED_CA_NO_POE
			}

			item = item.setNextItem(certificateSignatureValid(certificate, subContext));
		}

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
			certificateChain = token.getCertificateChain();
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
		return new ProspectiveCertificateChainCheck(result, token, constraint);
	}

	private ChainItem<XmlPCV> certificateSignatureValid(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = policy.getCertificateSignatureConstraint(context, subContext);
		return new CertificateSignatureValidCheck<XmlPCV>(result, certificate, constraint);
	}

	private ChainItem<XmlPCV> validationTimeSliding() {
		ValidationTimeSliding validationTimeSliding = new ValidationTimeSliding(token, currentTime, context, poe, policy);
		XmlVTS vts = validationTimeSliding.execute();
		bbb.setVTS(vts);
		if (isValid(vts)) {
			controlTime = vts.getControlTime();
		}

		return new ValidationTimeSlidingCheck(result, vts, getFailLevelConstraint());
	}

	private ChainItem<XmlPCV> cryptographicCheck(XmlPCV result, CertificateWrapper certificate, Date validationTime, SubContext subContext) {
		CryptographicConstraint constraint = policy.getCertificateCryptographicConstraint(context, subContext);
		return new CryptographicCheck<XmlPCV>(result, certificate, validationTime, constraint);
	}

	@Override
	protected void addAdditionalInfo() {
		result.setControlTime(controlTime); // can be null
	}

}
