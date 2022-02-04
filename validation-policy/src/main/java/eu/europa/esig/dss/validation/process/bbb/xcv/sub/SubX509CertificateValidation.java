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
package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRevocationInformation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.SubContext;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.IntValueConstraint;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.ValueConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.crs.CertificateRevocationSelector;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.RevocationFreshnessChecker;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.RevocationDataAvailableCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.AuthorityInfoAccessPresentCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateIssuedToLegalPersonCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateIssuedToNaturalPersonCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateMinQcEuRetentionPeriodCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateMinQcTransactionLimitCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateNotOnHoldCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateNotRevokedCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateNotSelfSignedCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificatePS2DQcCompetentAuthorityIdCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificatePS2DQcCompetentAuthorityNameCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificatePS2DQcRolesOfPSPCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificatePolicyIdsCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificatePolicyQualifiedIdsCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificatePolicySupportedByQSCDIdsCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateQcCCLegislationCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateQcComplianceCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateQcEuLimitValueCurrencyCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateQcEuPDSLocationCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateQcSSCDCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateQcTypeCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateRevocationSelectorResultCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateSelfSignedCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateSemanticsIdentifierCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateSignatureValidCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateValidityRangeCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CommonNameCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CountryCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.ExtendedKeyUsageCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.GivenNameCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.IdPkixOcspNoCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.KeyUsageCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.OrganizationNameCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.OrganizationUnitCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.PseudoUsageCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.PseudonymCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationFreshnessCheckerResultCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationInfoAccessPresentCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationIssuerTrustedCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationIssuerValidityRangeCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.SerialNumberCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.SurnameCheck;

import java.util.Date;

/**
 * The sub X509 certificate validation
 */
public class SubX509CertificateValidation extends Chain<XmlSubXCV> {

	/** The certificate to check */
	private final CertificateWrapper currentCertificate;

	/** Validation time */
	private final Date currentTime;

	/** Validation context */
	private final Context context;

	/** Validation subContext */
	private final SubContext subContext;

	/** Validation policy */
	private final ValidationPolicy validationPolicy;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param currentCertificate {@link CertificateWrapper}
	 * @param currentTime {@link Date} validation time
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @param validationPolicy {@link ValidationPolicy}
	 */
	public SubX509CertificateValidation(I18nProvider i18nProvider, CertificateWrapper currentCertificate, Date currentTime, 
			Context context, SubContext subContext, ValidationPolicy validationPolicy) {
		super(i18nProvider, new XmlSubXCV());
		result.setId(currentCertificate.getId());
		result.setTrustAnchor(currentCertificate.isTrusted());
		result.setSelfSigned(currentCertificate.isSelfSigned());

		this.currentCertificate = currentCertificate;
		this.currentTime = currentTime;

		this.context = context;
		this.subContext = subContext;
		this.validationPolicy = validationPolicy;
	}
	
	@Override
	protected MessageTag getTitle() {
		return MessageTag.SUB_XCV;
	}

	@Override
	protected void initChain() {
		// Skip for Trusted Certificate
		if (currentCertificate.isTrusted()) {
			return;
		}

		ChainItem<XmlSubXCV> item = firstItem = serialNumber(currentCertificate, subContext);

		item = item.setNextItem(surname(currentCertificate, subContext));

		item = item.setNextItem(givenName(currentCertificate, subContext));

		item = item.setNextItem(commonName(currentCertificate, subContext));

		item = item.setNextItem(pseudoUsage(currentCertificate, subContext));

		item = item.setNextItem(pseudonym(currentCertificate, subContext));

		item = item.setNextItem(country(currentCertificate, subContext));

		item = item.setNextItem(organizationUnit(currentCertificate, subContext));

		item = item.setNextItem(organizationName(currentCertificate, subContext));

		item = item.setNextItem(selfSigned(currentCertificate, subContext));

		item = item.setNextItem(notSelfSigned(currentCertificate, subContext));

		item = item.setNextItem(certificatePolicyIds(currentCertificate, subContext));

		item = item.setNextItem(certificatePolicyQualifiedIds(currentCertificate, subContext));

		item = item.setNextItem(certificatePolicySupportedByQSCDIds(currentCertificate, subContext));

		item = item.setNextItem(certificateQcCompliance(currentCertificate, subContext));

		item = item.setNextItem(certificateQcEuLimitValueCurrency(currentCertificate, subContext));

		item = item.setNextItem(certificateMinQcEuLimitValue(currentCertificate, subContext));

		item = item.setNextItem(certificateQcEuRetentionPeriod(currentCertificate, subContext));

		item = item.setNextItem(certificateQcSSCD(currentCertificate, subContext));

		item = item.setNextItem(certificateQcEuPDSLocation(currentCertificate, subContext));

		item = item.setNextItem(certificateQcType(currentCertificate, subContext));

		item = item.setNextItem(certificateQcCCLegislation(currentCertificate, subContext));

		item = item.setNextItem(certificateIssuedToNaturalPerson(currentCertificate, subContext));

		item = item.setNextItem(certificateIssuedToLegalPerson(currentCertificate, subContext));

		item = item.setNextItem(certificateSemanticsIdentifier(currentCertificate, subContext));

		item = item.setNextItem(certificatePS2DQcRolesOfPSP(currentCertificate, subContext));

		item = item.setNextItem(certificatePS2DQcCompetentAuthorityName(currentCertificate, subContext));

		item = item.setNextItem(certificatePS2DQcCompetentAuthorityId(currentCertificate, subContext));

		item = item.setNextItem(certificateSignatureValid(currentCertificate, subContext));

		item = item.setNextItem(keyUsage(currentCertificate, subContext));

		item = item.setNextItem(extendedKeyUsage(currentCertificate, subContext));

		item = item.setNextItem(aiaPresent(currentCertificate, subContext));

		CertificateRevocationWrapper latestCertificateRevocation = null;
		
		if (currentCertificate.isIdPkixOcspNoCheck()) {
			item = item.setNextItem(idPkixOcspNoCheck(currentCertificate));
		}

		if (ValidationProcessUtils.isRevocationCheckRequired(currentCertificate)) {

			item = item.setNextItem(revocationInfoAccessPresent(currentCertificate, subContext));
			
			item = item.setNextItem(revocationDataPresent(currentCertificate, subContext));

			if (Utils.isCollectionNotEmpty(currentCertificate.getCertificateRevocationData())) {

				CertificateRevocationSelector certificateRevocationSelector = new CertificateRevocationSelector(
						i18nProvider, currentCertificate, currentTime, validationPolicy);
				XmlCRS xmlCRS = certificateRevocationSelector.execute();
				result.setCRS(xmlCRS);

				item = item.setNextItem(checkCertificateRevocationSelectorResult(xmlCRS));

				latestCertificateRevocation = certificateRevocationSelector.getLatestAcceptableCertificateRevocation();

				if (latestCertificateRevocation != null && latestCertificateRevocation.isRevoked()) {
					attachRevocationInformation(latestCertificateRevocation);
				}

				if (isValid(xmlCRS)) {

					item = item.setNextItem(certificateNotRevoked(latestCertificateRevocation, subContext));

					item = item.setNextItem(certificateNotOnHold(latestCertificateRevocation, subContext));

					RevocationFreshnessChecker rfc = new RevocationFreshnessChecker(i18nProvider, latestCertificateRevocation,
							currentTime, context, subContext, validationPolicy);
					XmlRFC rfcResult = rfc.execute();
					result.setRFC(rfcResult);

					item = item.setNextItem(checkRevocationFreshnessCheckerResult(rfcResult));

				}

			}
			
		}

		item = item.setNextItem(certificateCryptographic(currentCertificate, context, subContext));

		if (SubContext.SIGNING_CERT == subContext) {

			item = item.setNextItem(certificateValidityRange(currentCertificate, latestCertificateRevocation, subContext));

			if (latestCertificateRevocation != null) {
				CertificateWrapper revocationIssuerCertificate = latestCertificateRevocation.getSigningCertificate();
				if (revocationIssuerCertificate != null) {
					if (revocationIssuerCertificate.isTrusted()) {
						item = item.setNextItem(revocationDataIssuerTrusted(revocationIssuerCertificate));
					} else  {
						item = item.setNextItem(revocationIssuerValidityRange(latestCertificateRevocation, subContext));
					}
				}
			}

		}

	}

	private void attachRevocationInformation(CertificateRevocationWrapper certificateRevocation) {
		XmlRevocationInformation revocationInfo = new XmlRevocationInformation();
		revocationInfo.setCertificateId(currentCertificate.getId());
		revocationInfo.setRevocationId(certificateRevocation.getId());
		revocationInfo.setRevocationDate(certificateRevocation.getRevocationDate());
		revocationInfo.setReason(certificateRevocation.getReason());
		result.setRevocationInfo(revocationInfo);
	}

	private ChainItem<XmlSubXCV> certificateValidityRange(CertificateWrapper certificate, CertificateRevocationWrapper usedCertificateRevocation,
														  SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateNotExpiredConstraint(context, subContext);
		return new CertificateValidityRangeCheck<>(i18nProvider, result, certificate, usedCertificateRevocation, currentTime, constraint);
	}

	private ChainItem<XmlSubXCV> revocationDataIssuerTrusted(CertificateWrapper revocationIssuer) {
		return new RevocationIssuerTrustedCheck<>(i18nProvider, result, revocationIssuer, getWarnLevelConstraint());
	}

	private ChainItem<XmlSubXCV> revocationIssuerValidityRange(CertificateRevocationWrapper usedCertificateRevocation,
															   SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getRevocationIssuerNotExpiredConstraint(context, subContext);
		return new RevocationIssuerValidityRangeCheck<>(i18nProvider, result, usedCertificateRevocation, currentTime, constraint);
	}

	private ChainItem<XmlSubXCV> keyUsage(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateKeyUsageConstraint(context, subContext);
		return new KeyUsageCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> extendedKeyUsage(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateExtendedKeyUsageConstraint(context, subContext);
		return new ExtendedKeyUsageCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> aiaPresent(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateAuthorityInfoAccessPresentConstraint(context, subContext);
		return new AuthorityInfoAccessPresentCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> revocationInfoAccessPresent(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateRevocationInfoAccessPresentConstraint(context, subContext);
		return new RevocationInfoAccessPresentCheck(i18nProvider, result, certificate, constraint);
	}
	
	private ChainItem<XmlSubXCV> revocationDataPresent(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getRevocationDataAvailableConstraint(context, subContext);
		return new RevocationDataAvailableCheck<>(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> checkCertificateRevocationSelectorResult(XmlCRS crsResult) {
		LevelConstraint constraint = validationPolicy.getAcceptableRevocationDataFoundConstraint(context, subContext);
		return new CertificateRevocationSelectorResultCheck<>(i18nProvider, result, crsResult, constraint);
	}
	
	private ChainItem<XmlSubXCV> checkRevocationFreshnessCheckerResult(XmlRFC rfcResult) {
		return new RevocationFreshnessCheckerResultCheck<>(i18nProvider, result, rfcResult, getFailLevelConstraint());
	}

	private ChainItem<XmlSubXCV> surname(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateSurnameConstraint(context, subContext);
		return new SurnameCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> givenName(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateGivenNameConstraint(context, subContext);
		return new GivenNameCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> commonName(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateCommonNameConstraint(context, subContext);
		return new CommonNameCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> pseudonym(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificatePseudonymConstraint(context, subContext);
		return new PseudonymCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> country(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateCountryConstraint(context, subContext);
		return new CountryCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> organizationName(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateOrganizationNameConstraint(context, subContext);
		return new OrganizationNameCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> organizationUnit(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateOrganizationUnitConstraint(context, subContext);
		return new OrganizationUnitCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> serialNumber(CertificateWrapper signingCertificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateSerialNumberConstraint(context, subContext);
		return new SerialNumberCheck(i18nProvider, result, signingCertificate, constraint);
	}

	private ChainItem<XmlSubXCV> pseudoUsage(CertificateWrapper signingCertificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificatePseudoUsageConstraint(context, subContext);
		return new PseudoUsageCheck(i18nProvider, result, signingCertificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateSignatureValid(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateSignatureConstraint(context, subContext);
		return new CertificateSignatureValidCheck<>(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateNotRevoked(CertificateRevocationWrapper latestCertificateRevocation, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateNotRevokedConstraint(context, subContext);
		return new CertificateNotRevokedCheck(i18nProvider, result, latestCertificateRevocation, currentTime, constraint, subContext);
	}

	private ChainItem<XmlSubXCV> certificateNotOnHold(CertificateRevocationWrapper latestCertificateRevocation, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateNotOnHoldConstraint(context, subContext);
		return new CertificateNotOnHoldCheck(i18nProvider, result, latestCertificateRevocation, currentTime, constraint);
	}

	private ChainItem<XmlSubXCV> notSelfSigned(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateNotSelfSignedConstraint(context, subContext);
		return new CertificateNotSelfSignedCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> selfSigned(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateSelfSignedConstraint(context, subContext);
		return new CertificateSelfSignedCheck<>(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificatePolicyIds(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificatePolicyIdsConstraint(context, subContext);
		return new CertificatePolicyIdsCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificatePolicyQualifiedIds(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificatePolicyQualificationIdsConstraint(context, subContext);
		return new CertificatePolicyQualifiedIdsCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificatePolicySupportedByQSCDIds(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificatePolicySupportedByQSCDIdsConstraint(context, subContext);
		return new CertificatePolicySupportedByQSCDIdsCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateQcCompliance(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateQCComplianceConstraint(context, subContext);
		return new CertificateQcComplianceCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateMinQcEuLimitValue(CertificateWrapper certificate, SubContext subContext) {
		IntValueConstraint constraint = validationPolicy.getCertificateMinQcEuLimitValueConstraint(context, subContext);
		return new CertificateMinQcTransactionLimitCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateQcEuLimitValueCurrency(CertificateWrapper certificate, SubContext subContext) {
		ValueConstraint constraint = validationPolicy.getCertificateQcEuLimitValueCurrencyConstraint(context, subContext);
		return new CertificateQcEuLimitValueCurrencyCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateQcEuRetentionPeriod(CertificateWrapper certificate, SubContext subContext) {
		IntValueConstraint constraint = validationPolicy.getCertificateMinQcEuRetentionPeriodConstraint(context, subContext);
		return new CertificateMinQcEuRetentionPeriodCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateQcSSCD(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateQcSSCDConstraint(context, subContext);
		return new CertificateQcSSCDCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateQcEuPDSLocation(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateQcEuPDSLocationConstraint(context, subContext);
		return new CertificateQcEuPDSLocationCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateQcType(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateQcTypeConstraint(context, subContext);
		return new CertificateQcTypeCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateQcCCLegislation(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateQcCCLegislationConstraint(context, subContext);
		return new CertificateQcCCLegislationCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateIssuedToNaturalPerson(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateIssuedToNaturalPersonConstraint(context, subContext);
		return new CertificateIssuedToNaturalPersonCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateIssuedToLegalPerson(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateIssuedToLegalPersonConstraint(context, subContext);
		return new CertificateIssuedToLegalPersonCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateSemanticsIdentifier(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateSemanticsIdentifierConstraint(context, subContext);
		return new CertificateSemanticsIdentifierCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificatePS2DQcRolesOfPSP(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificatePS2DQcTypeRolesOfPSPConstraint(context, subContext);
		return new CertificatePS2DQcRolesOfPSPCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificatePS2DQcCompetentAuthorityName(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificatePS2DQcCompetentAuthorityNameConstraint(context, subContext);
		return new CertificatePS2DQcCompetentAuthorityNameCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificatePS2DQcCompetentAuthorityId(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificatePS2DQcCompetentAuthorityIdConstraint(context, subContext);
		return new CertificatePS2DQcCompetentAuthorityIdCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> idPkixOcspNoCheck(CertificateWrapper certificateWrapper) {
		return new IdPkixOcspNoCheck<>(i18nProvider, result, certificateWrapper, getWarnLevelConstraint());
	}

	private ChainItem<XmlSubXCV> certificateCryptographic(CertificateWrapper certificate, Context context, SubContext subcontext) {
		CryptographicConstraint cryptographicConstraint = validationPolicy.getCertificateCryptographicConstraint(context, subcontext);
		MessageTag position = ValidationProcessUtils.getCertificateChainCryptoPosition(context);
		return new CryptographicCheck<>(i18nProvider, result, certificate, position, currentTime, cryptographicConstraint);
	}

	@Override
	protected void collectAdditionalMessages(XmlConclusion conclusion) {
		super.collectAdditionalMessages(conclusion);
		XmlCRS xmlCRS = result.getCRS();
		if (xmlCRS != null && isValid(xmlCRS)) {
			collectAllMessages(conclusion, xmlCRS.getConclusion());
		}
		XmlRFC xmlRFC = result.getRFC();
		if (xmlRFC != null && isValid(xmlRFC)) {
			collectAllMessages(conclusion, xmlRFC.getConclusion());
		}
	}

}
