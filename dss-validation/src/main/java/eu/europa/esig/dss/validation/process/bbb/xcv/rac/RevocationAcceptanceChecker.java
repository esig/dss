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
package eu.europa.esig.dss.validation.process.bbb.xcv.rac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.SubContext;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.CertificateValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.SignatureIntactCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.SignatureIntactWithIdCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.ProspectiveCertificateChainCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.crs.CertificateRevocationSelector;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationCertHashMatchCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationCertHashPresenceCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationDataKnownCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationHasInformationAboutCertificateCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationIssuerKnownCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationAfterCertificateIssuanceCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationIssuerRevocationDataAvailableCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationIssuerValidAtProductionTimeCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationResponderIdMatchCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.SelfIssuedOCSPCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.ThisUpdatePresenceCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateRevocationSelectorResultCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateSelfSignedCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationDataRequiredCheck;

import java.util.Date;
import java.util.Set;

/**
 * Checks if the revocation is acceptable and can be used
 */
public class RevocationAcceptanceChecker extends Chain<XmlRAC> {

	/** The certificate in question */
	private final CertificateWrapper certificate;

	/** The revocation data */
	private final CertificateRevocationWrapper revocationData;

	/** Validation time */
	private final Date controlTime;

	/** Validation policy */
	private final ValidationPolicy policy;

	/** Internal set of processed tokens (avoids infinite loop) */
	private final Set<String> validatedTokens;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param certificate {@link CertificateWrapper}
	 * @param revocationData {@link CertificateRevocationWrapper}
	 * @param controlTime {@link Date}
	 * @param policy {@link ValidationPolicy}
	 * @param validatedTokens a set of token {@link String} identifiers that have been already processed
	 */
	public RevocationAcceptanceChecker(I18nProvider i18nProvider, CertificateWrapper certificate,
										CertificateRevocationWrapper revocationData, Date controlTime,
										ValidationPolicy policy, Set<String> validatedTokens) {
		super(i18nProvider, new XmlRAC());
		this.certificate = certificate;
		this.revocationData = revocationData;
		this.controlTime = controlTime;
		this.policy = policy;
		this.validatedTokens = validatedTokens;

		result.setId(revocationData.getId());
		result.setRevocationThisUpdate(revocationData.getThisUpdate());
		result.setRevocationProductionDate(revocationData.getProductionDate());
		this.validatedTokens.add(certificate.getId());
	}

	@Override
	protected MessageTag getTitle() {
		return MessageTag.RAC;
	}

	@Override
	protected void initChain() {

		ChainItem<XmlRAC> item = firstItem = revocationDataKnown();

		item = item.setNextItem(issuerCertificateKnown());

		item = item.setNextItem(prospectiveCertificateChain(revocationData.getSigningCertificate()));

		item = item.setNextItem(revocationDataIntact());

		item = item.setNextItem(thisUpdate());

		/*
		 * certHash extension can be present in an OCSP Response. If present, a digest match indicates the OCSP
		 * responder knows the certificate as we have it, and so also its revocation state
		 */
		if (RevocationType.OCSP.equals(revocationData.getRevocationType())) {

			item = item.setNextItem(issuerValidAtProductionTime());

			item = item.setNextItem(revocationResponderIdMatch());

			item = item.setNextItem(revocationCertHashPresent());
			
			if (revocationData.isCertHashExtensionPresent()) {
				item = item.setNextItem(revocationCertHashMatch());
			}

			item = item.setNextItem(selfIssuedOcsp());

		}

		item = item.setNextItem(revocationAfterCertIssuance());

		item = item.setNextItem(revocationHasInformationAboutCertificate());
		
		for (CertificateWrapper revocationCertificate : revocationData.getCertificateChain()) {
			SubContext subContext = revocationData.getSigningCertificate().getId().equals(revocationCertificate.getId()) ?
					SubContext.SIGNING_CERT : SubContext.CA_CERTIFICATE;
			
			if (isTrustAnchor(revocationCertificate, subContext)) {
				break;
			}
			
			if (isTokenValidated(revocationCertificate)) {
				continue;
			}
			
			item = item.setNextItem(certificateIntact(revocationCertificate));

			if (revocationCertificate.isSelfSigned()) {
				item = item.setNextItem(selfSigned(revocationCertificate));
			}

			RevocationDataRequiredCheck<XmlRAC> revocationDataRequired = revocationDataRequired(revocationCertificate, subContext);
			if (revocationDataRequired.process()) {
				
				item = item.setNextItem(revocationDataPresentForRevocationChain(revocationCertificate, subContext));

				if (Utils.isCollectionNotEmpty(revocationCertificate.getCertificateRevocationData())) {

					CertificateRevocationSelector certificateRevocationSelector = new CertificateRevocationSelector(
							i18nProvider, revocationCertificate, controlTime, policy, validatedTokens);
					XmlCRS xmlCRS = certificateRevocationSelector.execute();
					result.setCRS(xmlCRS);

					item = item.setNextItem(checkCertificateRevocationSelectorResult(xmlCRS, subContext));

				}
				
			} else {
				item = item.setNextItem(revocationDataRequired);
			}
			
		}
		
	}

	private ChainItem<XmlRAC> revocationDataKnown() {
		return new RevocationDataKnownCheck(i18nProvider, result, revocationData, policy.getUnknownStatusConstraint());
	}

	private ChainItem<XmlRAC> revocationResponderIdMatch() {
		LevelConstraint constraint = policy.getOCSPResponseResponderIdMatchConstraint();
		return new RevocationResponderIdMatchCheck(i18nProvider, result, revocationData, constraint);
	}

	private ChainItem<XmlRAC> revocationCertHashPresent() {
		LevelConstraint constraint = policy.getOCSPResponseCertHashPresentConstraint();
		return new RevocationCertHashPresenceCheck(i18nProvider, result, revocationData, constraint);
	}

	private ChainItem<XmlRAC> revocationCertHashMatch() {
		LevelConstraint constraint = policy.getOCSPResponseCertHashMatchConstraint();
		return new RevocationCertHashMatchCheck(i18nProvider, result, revocationData, constraint);
	}

	private ChainItem<XmlRAC> selfIssuedOcsp() {
		LevelConstraint constraint = policy.getSelfIssuedOCSPConstraint();
		return new SelfIssuedOCSPCheck(i18nProvider, result, certificate, revocationData, constraint);
	}

	private ChainItem<XmlRAC> thisUpdate() {
		LevelConstraint constraint = policy.getThisUpdatePresentConstraint();
		return new ThisUpdatePresenceCheck(i18nProvider, result, revocationData, constraint);
	}
	
	private ChainItem<XmlRAC> issuerCertificateKnown() {
		LevelConstraint constraint = policy.getRevocationIssuerKnownConstraint();
		return new RevocationIssuerKnownCheck(i18nProvider, result, revocationData, constraint);
	}

	private ChainItem<XmlRAC> issuerValidAtProductionTime() {
		LevelConstraint constraint = policy.getRevocationIssuerValidAtProductionTimeConstraint();
		return new RevocationIssuerValidAtProductionTimeCheck(i18nProvider, result, revocationData, constraint);
	}

	private ChainItem<XmlRAC> revocationAfterCertIssuance() {
		LevelConstraint constraint = policy.getRevocationAfterCertificateIssuanceConstraint();
		return new RevocationAfterCertificateIssuanceCheck(i18nProvider, result, certificate, revocationData, constraint);
	}

	private ChainItem<XmlRAC> revocationHasInformationAboutCertificate() {
		LevelConstraint constraint = policy.getRevocationHasInformationAboutCertificateConstraint();
		return new RevocationHasInformationAboutCertificateCheck(i18nProvider, result, certificate, revocationData, constraint);
	}

	private ChainItem<XmlRAC> revocationDataIntact() {
		LevelConstraint constraint = policy.getSignatureIntactConstraint(Context.REVOCATION);
		return new SignatureIntactCheck<>(i18nProvider, result, revocationData, Context.REVOCATION, constraint);
	}

	private ChainItem<XmlRAC> prospectiveCertificateChain(CertificateWrapper signingCertificate) {
		LevelConstraint constraint = policy.getProspectiveCertificateChainConstraint(Context.REVOCATION);
		return new ProspectiveCertificateChainCheck<>(i18nProvider, result, signingCertificate, Context.REVOCATION, constraint);
	}
	
	private boolean isTokenValidated(TokenProxy token) {
		boolean validated = validatedTokens.contains(token.getId());
		validatedTokens.add(token.getId());
		return validated;
	}
	
	private ChainItem<XmlRAC> certificateIntact(CertificateWrapper certificate) {
		LevelConstraint constraint = policy.getSignatureIntactConstraint(Context.CERTIFICATE);
		return new SignatureIntactWithIdCheck<>(i18nProvider, result, certificate, Context.CERTIFICATE, constraint);
	}

	private ChainItem<XmlRAC> selfSigned(CertificateWrapper certificate) {
		return new CertificateSelfSignedCheck<>(i18nProvider, result, certificate, getWarnLevelConstraint());
	}
	
	private ChainItem<XmlRAC> revocationDataPresentForRevocationChain(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = policy.getRevocationDataAvailableConstraint(Context.REVOCATION, subContext);
		return new RevocationIssuerRevocationDataAvailableCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlRAC> checkCertificateRevocationSelectorResult(XmlCRS crsResult, SubContext subContext) {
		LevelConstraint constraint = policy.getAcceptableRevocationDataFoundConstraint(Context.REVOCATION, subContext);
		return new CertificateRevocationSelectorResultCheck<>(i18nProvider, result, crsResult, constraint);
	}

	private RevocationDataRequiredCheck<XmlRAC> revocationDataRequired(CertificateWrapper certificate, SubContext subContext) {
		CertificateValuesConstraint constraint = policy.getRevocationDataSkipConstraint(Context.REVOCATION, subContext);
		LevelConstraint sunsetDateConstraint = policy.getCertificateSunsetDateConstraint(Context.REVOCATION, subContext);
		return new RevocationDataRequiredCheck<>(i18nProvider, result, certificate, controlTime, sunsetDateConstraint, constraint);
	}

	private boolean isTrustAnchor(CertificateWrapper certificateWrapper, SubContext subContext) {
		LevelConstraint sunsetDateConstraint = policy.getCertificateSunsetDateConstraint(Context.REVOCATION, subContext);
		return ValidationProcessUtils.isTrustAnchor(certificateWrapper, controlTime, sunsetDateConstraint);
	}

	@Override
	protected void collectAdditionalMessages(XmlConclusion conclusion) {
		super.collectAdditionalMessages(conclusion);

		XmlCRS crs = result.getCRS();
		if (crs != null) {
			super.collectAllMessages(conclusion, crs.getConclusion());
		}
	}

}
