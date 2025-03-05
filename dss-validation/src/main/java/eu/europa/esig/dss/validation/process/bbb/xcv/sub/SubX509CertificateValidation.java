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
import eu.europa.esig.dss.policy.jaxb.CertificateValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.IntValueConstraint;
import eu.europa.esig.dss.policy.jaxb.Level;
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
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.BasicConstraintsCACheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.BasicConstraintsMaxPathLengthCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateForbiddenExtensionsCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateIssuedToLegalPersonCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateIssuedToNaturalPersonCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateIssuerNameCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateMinQcEuRetentionPeriodCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateMinQcTransactionLimitCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateNameConstraintsCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateNotOnHoldCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateNotRevokedCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateNotSelfSignedCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificatePS2DQcCompetentAuthorityIdCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificatePS2DQcCompetentAuthorityNameCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificatePS2DQcRolesOfPSPCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificatePolicyIdsCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificatePolicyQualifiedIdsCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificatePolicySupportedByQSCDIdsCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificatePolicyTreeCheck;
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
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateSupportedCriticalExtensionsCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.CertificateValidationBeforeSunsetDateCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateValidityRangeCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CommonNameCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CountryCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.EmailCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.ExtendedKeyUsageCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.GivenNameCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.KeyUsageCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.LocalityCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.NoRevAvailCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.OrganizationIdentifierCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.OrganizationNameCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.OrganizationUnitCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.OtherTrustAnchorExistsCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.PseudoUsageCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.PseudonymCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationDataRequiredCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationFreshnessCheckerResultCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationInfoAccessPresentCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationIssuerTrustedCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationIssuerValidityRangeCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.SerialNumberCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.StateCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.SurnameCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.TitleCheck;

import java.util.Date;

/**
 * The sub X509 certificate validation
 */
public class SubX509CertificateValidation extends Chain<XmlSubXCV> {

	/** The certificate to check */
	private final CertificateWrapper currentCertificate;

	/** Validation time */
	private final Date validationDate;

	/** Current time when validation is performed */
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
	 * @param validationDate {@link Date} validation time returned by the corresponding validation model
	 * @param currentTime {@link Date} time when validation is performed
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @param validationPolicy {@link ValidationPolicy}
	 */
	public SubX509CertificateValidation(I18nProvider i18nProvider, CertificateWrapper currentCertificate, Date validationDate,
			Date currentTime, Context context, SubContext subContext, ValidationPolicy validationPolicy) {
		super(i18nProvider, new XmlSubXCV());
		result.setId(currentCertificate.getId());
		result.setTrustAnchor(currentCertificate.isTrusted());
		result.setSelfSigned(currentCertificate.isSelfSigned());

		this.currentCertificate = currentCertificate;
		this.validationDate = validationDate;
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
		ChainItem<XmlSubXCV> item = null;

		if (currentCertificate.isTrusted()) {

			if (currentCertificate.getTrustStartDate() != null || currentCertificate.getTrustSunsetDate() != null) {

				item = firstItem = validationBeforeSunsetDate(currentCertificate, subContext, currentTime);

				if (!ValidationProcessUtils.isTrustAnchor(currentCertificate, currentTime, getFailLevelConstraint())) {
					item = item.setNextItem(otherTrustAnchorAvailable(currentCertificate, subContext));
				}

			}

			if (isTrustAnchorReached(currentCertificate, subContext)) {
				// Skip for Trusted Certificate
				return;
			}

		}

		if (item == null) {
			item = firstItem = serialNumber(currentCertificate, subContext);
		} else {
			item = item.setNextItem(serialNumber(currentCertificate, subContext));
		}

		item = item.setNextItem(surname(currentCertificate, subContext));

		item = item.setNextItem(givenName(currentCertificate, subContext));

		item = item.setNextItem(commonName(currentCertificate, subContext));

		item = item.setNextItem(pseudoUsage(currentCertificate, subContext));

		item = item.setNextItem(pseudonym(currentCertificate, subContext));

		item = item.setNextItem(title(currentCertificate, subContext));

		item = item.setNextItem(email(currentCertificate, subContext));

		item = item.setNextItem(country(currentCertificate, subContext));

		item = item.setNextItem(locality(currentCertificate, subContext));

		item = item.setNextItem(state(currentCertificate, subContext));

		item = item.setNextItem(organizationIdentifier(currentCertificate, subContext));

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

		item = item.setNextItem(ca(currentCertificate, subContext));

		item = item.setNextItem(issuerName(currentCertificate, subContext));

		item = item.setNextItem(maxPathLength(currentCertificate, subContext));

		item = item.setNextItem(keyUsage(currentCertificate, subContext));

		item = item.setNextItem(extendedKeyUsage(currentCertificate, subContext));

		item = item.setNextItem(aiaPresent(currentCertificate, subContext));

		item = item.setNextItem(policyTree(currentCertificate, subContext));

		item = item.setNextItem(nameConstraints(currentCertificate, subContext));

		if (currentCertificate.isNoRevAvail()) {
			item = item.setNextItem(noRevAvail(currentCertificate, subContext));
		}

		item = item.setNextItem(supportedCriticalCertificateExtensions(currentCertificate, subContext));

		item = item.setNextItem(forbiddenCertificateExtensions(currentCertificate, subContext));

		CertificateRevocationWrapper latestCertificateRevocation = null;

		RevocationDataRequiredCheck<XmlSubXCV> revocationDataRequired = revocationDataRequired(currentCertificate, subContext);

		boolean isRevocationDataRequired = revocationDataRequired.process();
		if (isRevocationDataRequired) {

			item = item.setNextItem(revocationInfoAccessPresent(currentCertificate, subContext));
			
			item = item.setNextItem(revocationDataPresent(currentCertificate, subContext));

			if (Utils.isCollectionNotEmpty(currentCertificate.getCertificateRevocationData())) {

				CertificateRevocationSelector certificateRevocationSelector = new CertificateRevocationSelector(
						i18nProvider, currentCertificate, validationDate, validationPolicy);
				XmlCRS xmlCRS = certificateRevocationSelector.execute();
				result.setCRS(xmlCRS);

				item = item.setNextItem(checkCertificateRevocationSelectorResult(xmlCRS));

				latestCertificateRevocation = certificateRevocationSelector.getLatestAcceptableCertificateRevocation();

				if (latestCertificateRevocation != null && latestCertificateRevocation.isRevoked()) {
					attachRevocationInformation(latestCertificateRevocation);
				}

				if (isValid(xmlCRS)) {

					item = item.setNextItem(certificateNotRevoked(latestCertificateRevocation, subContext, validationDate));

					item = item.setNextItem(certificateNotOnHold(latestCertificateRevocation, subContext, validationDate));

					RevocationFreshnessChecker rfc = new RevocationFreshnessChecker(i18nProvider, latestCertificateRevocation,
							validationDate, context, subContext, validationPolicy);
					XmlRFC rfcResult = rfc.execute();
					result.setRFC(rfcResult);

					item = item.setNextItem(checkRevocationFreshnessCheckerResult(rfcResult));

				}

			}
			
		} else {
			item = item.setNextItem(revocationDataRequired);
		}

		// NOTE: cryptographic constraint shall be validated against the current time,
		// and not against time returned by the used validation model
		item = item.setNextItem(certificateCryptographic(currentCertificate, context, subContext, currentTime));

		if (SubContext.SIGNING_CERT == subContext) {

			item = item.setNextItem(certificateValidityRange(currentCertificate,
					latestCertificateRevocation, isRevocationDataRequired, subContext, currentTime));

			if (latestCertificateRevocation != null) {
				CertificateWrapper revocationIssuerCertificate = latestCertificateRevocation.getSigningCertificate();
				if (revocationIssuerCertificate != null) {
					if (isTrustAnchor(revocationIssuerCertificate, context, SubContext.SIGNING_CERT)) {
						item = item.setNextItem(revocationDataIssuerTrusted(revocationIssuerCertificate));
					} else  {
						item = item.setNextItem(revocationIssuerValidityRange(latestCertificateRevocation, subContext, currentTime));
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

	private ChainItem<XmlSubXCV> validationBeforeSunsetDate(CertificateWrapper certificate, SubContext subContext, Date validationTime) {
		LevelConstraint constraint = validationPolicy.getCertificateSunsetDateConstraint(context, subContext);
		return new CertificateValidationBeforeSunsetDateCheck<>(i18nProvider, result, certificate, validationTime,
				ValidationProcessUtils.getConstraintOrMaxLevel(constraint, Level.WARN));
	}

	private ChainItem<XmlSubXCV> otherTrustAnchorAvailable(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateSunsetDateConstraint(context, subContext);
		return new OtherTrustAnchorExistsCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateValidityRange(CertificateWrapper certificate, CertificateRevocationWrapper usedCertificateRevocation,
														  boolean revocationDataRequired, SubContext subContext, Date validationTime) {
		LevelConstraint constraint = validationPolicy.getCertificateNotExpiredConstraint(context, subContext);
		boolean isRevocationIssuerTrusted = usedCertificateRevocation != null && usedCertificateRevocation.getSigningCertificate() != null
				&& isTrustAnchor(usedCertificateRevocation.getSigningCertificate(), Context.REVOCATION, SubContext.SIGNING_CERT);
		boolean revocationIssuerCheckEnforced = revocationIssuerCheckEnforced(context, subContext);
		return new CertificateValidityRangeCheck<>(i18nProvider, result, certificate, usedCertificateRevocation,
				revocationDataRequired, isRevocationIssuerTrusted, revocationIssuerCheckEnforced, validationTime, constraint);
	}

	private boolean revocationIssuerCheckEnforced(Context context, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getRevocationIssuerNotExpiredConstraint(context, subContext);
		return constraint != null && Level.FAIL == constraint.getLevel();
	}

	private ChainItem<XmlSubXCV> revocationDataIssuerTrusted(CertificateWrapper revocationIssuer) {
		LevelConstraint revocationDataSunsetDate = validationPolicy.getCertificateSunsetDateConstraint(
				Context.REVOCATION, SubContext.SIGNING_CERT);
		return new RevocationIssuerTrustedCheck<>(i18nProvider, result, revocationIssuer, currentTime,
				revocationDataSunsetDate, getWarnLevelConstraint());
	}

	private ChainItem<XmlSubXCV> revocationIssuerValidityRange(CertificateRevocationWrapper usedCertificateRevocation,
															   SubContext subContext, Date validationTime) {
		LevelConstraint constraint = validationPolicy.getRevocationIssuerNotExpiredConstraint(context, subContext);
		return new RevocationIssuerValidityRangeCheck<>(i18nProvider, result, usedCertificateRevocation, validationTime, constraint);
	}

	private ChainItem<XmlSubXCV> ca(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateCAConstraint(context, subContext);
		return new BasicConstraintsCACheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> issuerName(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateIssuerNameConstraint(context, subContext);
		return new CertificateIssuerNameCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> maxPathLength(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateMaxPathLengthConstraint(context, subContext);
		return new BasicConstraintsMaxPathLengthCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> keyUsage(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateKeyUsageConstraint(context, subContext);
		return new KeyUsageCheck(i18nProvider, result, certificate, context, subContext, constraint);
	}

	private ChainItem<XmlSubXCV> extendedKeyUsage(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateExtendedKeyUsageConstraint(context, subContext);
		return new ExtendedKeyUsageCheck(i18nProvider, result, certificate, context, subContext, constraint);
	}

	private ChainItem<XmlSubXCV> aiaPresent(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateAuthorityInfoAccessPresentConstraint(context, subContext);
		return new AuthorityInfoAccessPresentCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> policyTree(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificatePolicyTreeConstraint(context, subContext);
		return new CertificatePolicyTreeCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> nameConstraints(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateNameConstraintsConstraint(context, subContext);
		return new CertificateNameConstraintsCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> noRevAvail(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateNoRevAvailConstraint(context, subContext);
		return new NoRevAvailCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> supportedCriticalCertificateExtensions(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateSupportedCriticalExtensionsConstraint(context, subContext);
		return new CertificateSupportedCriticalExtensionsCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> forbiddenCertificateExtensions(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateForbiddenExtensionsConstraint(context, subContext);
		return new CertificateForbiddenExtensionsCheck(i18nProvider, result, certificate, constraint);
	}

	private RevocationDataRequiredCheck<XmlSubXCV> revocationDataRequired(CertificateWrapper certificate, SubContext subContext) {
		CertificateValuesConstraint constraint = validationPolicy.getRevocationDataSkipConstraint(context, subContext);
		LevelConstraint sunsetDateConstraint = validationPolicy.getCertificateSunsetDateConstraint(context, subContext);
		return new RevocationDataRequiredCheck<>(i18nProvider, result, certificate, currentTime, sunsetDateConstraint, constraint);
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

	private ChainItem<XmlSubXCV> title(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateTitleConstraint(context, subContext);
		return new TitleCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> email(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateEmailConstraint(context, subContext);
		return new EmailCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> country(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateCountryConstraint(context, subContext);
		return new CountryCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> locality(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateLocalityConstraint(context, subContext);
		return new LocalityCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> state(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateStateConstraint(context, subContext);
		return new StateCheck(i18nProvider, result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> organizationIdentifier(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateOrganizationIdentifierConstraint(context, subContext);
		return new OrganizationIdentifierCheck(i18nProvider, result, certificate, constraint);
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

	private ChainItem<XmlSubXCV> certificateNotRevoked(CertificateRevocationWrapper latestCertificateRevocation,
													   SubContext subContext, Date validationTime) {
		LevelConstraint constraint = validationPolicy.getCertificateNotRevokedConstraint(context, subContext);
		return new CertificateNotRevokedCheck(i18nProvider, result, latestCertificateRevocation, validationTime, constraint, subContext);
	}

	private ChainItem<XmlSubXCV> certificateNotOnHold(CertificateRevocationWrapper latestCertificateRevocation,
													  SubContext subContext, Date validationTime) {
		LevelConstraint constraint = validationPolicy.getCertificateNotOnHoldConstraint(context, subContext);
		return new CertificateNotOnHoldCheck(i18nProvider, result, latestCertificateRevocation, validationTime, constraint);
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

	private ChainItem<XmlSubXCV> certificateCryptographic(CertificateWrapper certificate, Context context,
														  SubContext subcontext, Date validationTime) {
		CryptographicConstraint cryptographicConstraint = validationPolicy.getCertificateCryptographicConstraint(context, subcontext);
		MessageTag position = ValidationProcessUtils.getCertificateChainCryptoPosition(context);
		return new CryptographicCheck<>(i18nProvider, result, certificate, position, validationTime, cryptographicConstraint);
	}

	private boolean isTrustAnchorReached(CertificateWrapper certificateWrapper, SubContext subContext) {
		return isTrustAnchor(certificateWrapper, context, subContext) || !certificateWrapper.isTrustedChain();
	}

	private boolean isTrustAnchor(CertificateWrapper certificateWrapper, Context context, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateSunsetDateConstraint(context, subContext);
		return ValidationProcessUtils.isTrustAnchor(certificateWrapper, currentTime, constraint);
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
