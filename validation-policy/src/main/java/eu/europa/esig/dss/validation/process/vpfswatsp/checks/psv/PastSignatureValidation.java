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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.SubContext;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.validation.process.BasicBuildingBlockDefinition;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicRevocationsCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.pcv.PastCertificateValidation;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.BestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpirationCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.BestSignatureTimeNotBeforeCertificateIssuanceCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.CurrentTimeIndicationCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.POEExistsCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.PastCertificateValidationAcceptableCheck;

public class PastSignatureValidation extends Chain<XmlPSV> {

	private final TokenProxy token;
	private final DiagnosticData diagnosticData;
	private final XmlBasicBuildingBlocks bbb;
	private final POEExtraction poe;
	private final Date currentTime;

	private final ValidationPolicy policy;
	private final Context context;

	public PastSignatureValidation(TokenProxy token, DiagnosticData diagnosticData, XmlBasicBuildingBlocks bbb, POEExtraction poe, Date currentTime,
			ValidationPolicy policy, Context context) {
		super(new XmlPSV());
		result.setTitle(BasicBuildingBlockDefinition.PAST_SIGNATURE_VALIDATION.getTitle());

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

		final Indication currentTimeIndication = bbb.getConclusion().getIndication();
		final SubIndication currentTimeSubIndication = bbb.getConclusion().getSubIndication();
		final List<XmlName> currentTimeErrors = bbb.getConclusion().getErrors();

		PastCertificateValidation pcv = new PastCertificateValidation(token, diagnosticData, bbb, poe, currentTime, policy, context);
		XmlPCV pcvResult = pcv.execute();
		bbb.setPCV(pcvResult);

		/*
		 * 1) The building block shall perform the past certificate validation process with the following inputs: the
		 * signature, the target certificate, the X.509 validation parameters, certificate validation data, chain
		 * constraints, cryptographic constraints and the set of POEs. If it returns PASSED/validation time, the
		 * building block shall go to the next step. Otherwise, the building block shall return the current time status
		 * and sub-indication with an explanation of the failure.
		 */
		ChainItem<XmlPSV> item = firstItem = pastCertificateValidationAcceptableCheck(pcvResult);

		Date controlTime = pcvResult.getControlTime();

		/*
		 * 2) If there is a POE of the signature value at (or before) the validation time returned in the previous step:
		 */
		if (controlTime != null && poe.isPOEExists(token.getId(), controlTime)) {

			result.setControlTime(controlTime);

			/*
			 * If current time indication/sub-indication is INDETERMINATE/REVOKED_NO_POE or INDETERMINATE/
			 * REVOKED_CA_NO_POE, the building block shall return PASSED.
			 */
			if (Indication.INDETERMINATE.equals(currentTimeIndication)
					&& (SubIndication.REVOKED_NO_POE.equals(currentTimeSubIndication) || SubIndication.REVOKED_CA_NO_POE.equals(currentTimeSubIndication))) {
				item = item.setNextItem(poeExist());
				return;
			}

			/*
			 * If current time indication/sub-indication is INDETERMINATE/OUT_OF_BOUNDS_NO_POE:
			 * 
			 * a) If best-signature-time (lowest time at which there exists a POE for the signature value in the set of
			 * POEs) is before the issuance date of the signing certificate (notBefore field), the building block
			 * shall return the indication INDETERMINATE with the sub-indication NOT_YET_VALID.
			 * 
			 * b) If best-signature-time (lowest time at which there exists a POE for the signature value in the set of
			 * POEs) is after the issuance date and before the expiration date of the signing certificate, the
			 * building block shall return the status indication PASSED.
			 */

			else if (Indication.INDETERMINATE.equals(currentTimeIndication) && SubIndication.OUT_OF_BOUNDS_NO_POE.equals(currentTimeSubIndication)) {

				Date bestSignatureTime = poe.getLowestPOETime(token.getId(), controlTime);
				CertificateWrapper signingCertificate = token.getSigningCertificate();

				item = item.setNextItem(bestSignatureTimeNotBeforeCertificateIssuance(bestSignatureTime, signingCertificate));
				item = item.setNextItem(bestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpiration(bestSignatureTime, signingCertificate));
				return;
			}

		}

		/*
		 * 3) If current time indication/ sub-indication is INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE and for
		 * each algorithm (or key size) in the list concerned by the failure, there is a POE for the material that
		 * uses this algorithm (or key size) at a time before the time up to which the algorithm in question was
		 * considered secure, the building block shall return the status indication PASSED.
		 */
		if (Indication.INDETERMINATE.equals(currentTimeIndication) && SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(currentTimeSubIndication)) {
			// check signature or timestamp itself
			Date bestSignatureTime = poe.getLowestPOETime(token.getId(), currentTime);
			item = item.setNextItem(poeUsedAlgorithmInSecureTimeExistsForEachAlgorithmConcernedByFailure(token, bestSignatureTime, context));
			
			// check the certificate chain
			CertificateWrapper signingCertificate = token.getSigningCertificate();
			for (CertificateWrapper certificate : token.getCertificateChain()) {
				if (certificate.isTrusted()) {
					break;
				}
				SubContext subContext = SubContext.CA_CERTIFICATE;
				if (certificate.getId().equals(signingCertificate.getId())) {
					subContext = SubContext.SIGNING_CERT;
				}
				bestSignatureTime = poe.getLowestPOETime(certificate.getId(), currentTime);
				item = item.setNextItem(poeUsedAlgorithmInSecureTimeExistsForEachAlgorithmConcernedByFailure(certificate, bestSignatureTime, context, subContext));
				// check related revocation data
				List<CryptographicCheck<XmlPSV>> revocationCryptographicChecks = getRevocationCryptographicChecks(certificate.getCertificateRevocationData(), currentTime);
				item = item.setNextItem(certificateRevocationCryptographicCheck(revocationCryptographicChecks, certificate));
			}
			return;
		}

		/*
		 * 4) In all other cases, the building block shall return the current time indication/ sub-indication together
		 * with an explanation of the failure.
		 */
		item = item.setNextItem(currentTimeIndicationCheck(currentTimeIndication, currentTimeSubIndication, currentTimeErrors));
	}

	private ChainItem<XmlPSV> currentTimeIndicationCheck(Indication currentTimeIndication, SubIndication currentTimeSubIndication,
			List<XmlName> currentTimeErrors) {
		return new CurrentTimeIndicationCheck(result, currentTimeIndication, currentTimeSubIndication, currentTimeErrors, getFailLevelConstraint());
	}

	private ChainItem<XmlPSV> pastCertificateValidationAcceptableCheck(XmlPCV pcvResult) {
		return new PastCertificateValidationAcceptableCheck(result, pcvResult, getFailLevelConstraint());
	}

	private ChainItem<XmlPSV> poeExist() {
		return new POEExistsCheck(result, getFailLevelConstraint());
	}

	private ChainItem<XmlPSV> bestSignatureTimeNotBeforeCertificateIssuance(Date bestSignatureTime, CertificateWrapper signingCertificate) {
		return new BestSignatureTimeNotBeforeCertificateIssuanceCheck(result, bestSignatureTime, signingCertificate, getFailLevelConstraint());
	}

	private ChainItem<XmlPSV> bestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpiration(Date bestSignatureTime,
			CertificateWrapper signingCertificate) {
		return new BestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpirationCheck(result, bestSignatureTime, signingCertificate,
				getFailLevelConstraint());
	}

	private CryptographicCheck<XmlPSV> poeUsedAlgorithmInSecureTimeExistsForEachAlgorithmConcernedByFailure(TokenProxy currentToken, 
			Date bestSignatureTime, Context context) {
		CryptographicConstraint cryptographicConstraint = policy.getSignatureCryptographicConstraint(context);
		return new CryptographicCheck<XmlPSV>(result, currentToken, bestSignatureTime, cryptographicConstraint);
	}
	
	private ChainItem<XmlPSV> poeUsedAlgorithmInSecureTimeExistsForEachAlgorithmConcernedByFailure(TokenProxy currentToken, 
			Date bestSignatureTime, Context context, SubContext subContext) {
		CryptographicConstraint cryptographicConstraint = policy.getCertificateCryptographicConstraint(context, subContext);
		return new CryptographicCheck<XmlPSV>(result, currentToken, bestSignatureTime, cryptographicConstraint);
	}
	
	private List<CryptographicCheck<XmlPSV>> getRevocationCryptographicChecks(List<CertificateRevocationWrapper> revocations, Date controlTime) {
		List<CryptographicCheck<XmlPSV>> revocationCryptographicChecks = new ArrayList<CryptographicCheck<XmlPSV>>();
		for (RevocationWrapper revocation : revocations) {
			Date bestSignatureTime = poe.getLowestPOETime(revocation.getId(), controlTime);
			revocationCryptographicChecks.add(
					poeUsedAlgorithmInSecureTimeExistsForEachAlgorithmConcernedByFailure(revocation, bestSignatureTime, Context.REVOCATION));
		}
		return revocationCryptographicChecks;
	}
	
	private ChainItem<XmlPSV> certificateRevocationCryptographicCheck(List<CryptographicCheck<XmlPSV>> revocationsChecks, CertificateWrapper certificate) {
		return new CryptographicRevocationsCheck<XmlPSV>(result, revocationsChecks, certificate.getId());
	}

}
