package eu.europa.esig.dss.validation.process.bbb.xcv;

import java.util.Date;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;

import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainCertificate;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.SubContext;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.CertificateCryptographicCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.CertificateExpirationCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.CertificateSignatureValidCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.CommonNameCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.CountryCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.GivenNameCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.IntermediateCertificateRevokedCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.KeyUsageCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.OrganizationNameCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.OrganizationUnitCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.ProspectiveCertificateChainCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.PseudonymCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.RevocationDataAvailableCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.RevocationDataTrustedCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.RevocationFreshnessCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.SigningCertificateIssuedToLegalPersonCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.SigningCertificateOnHoldCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.SigningCertificateQualifiedCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.SigningCertificateRevokedCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.SigningCertificateSupportedBySSCDCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.SigningCertificateTSLStatusAndValidityCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.SigningCertificateTSLStatusCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.SigningCertificateTSLValidityCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.SurnameCheck;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;
import eu.europa.esig.jaxb.policy.LevelConstraint;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;
import eu.europa.esig.jaxb.policy.TimeConstraint;

/**
 * 5.2.6 X.509 certificate validation This building block validates the signing
 * certificate at current time.
 */
public class X509CertificateValidation extends Chain<XmlXCV> {

	private final DiagnosticData diagnosticData;
	private final CertificateWrapper currentCertificate;
	private final Date currentTime;

	private final Context context;
	private final ValidationPolicy validationPolicy;

	public X509CertificateValidation(DiagnosticData diagnosticData, CertificateWrapper currentCertificate, Date currentTime, Context context,
			ValidationPolicy validationPolicy) {
		super(new XmlXCV());

		this.diagnosticData = diagnosticData;
		this.currentCertificate = currentCertificate;
		this.currentTime = currentTime;

		this.context = context;
		this.validationPolicy = validationPolicy;

	}

	@Override
	protected void initChain() {

		ChainItem<XmlXCV> item = firstItem = prospectiveCertificateChain();

		// Skip for Trusted Certificate
		if (currentCertificate.isTrusted()) {
			return;
		}

		// Checks SIGNING_CERT

		item = item.setNextItem(certificateExpiration(currentCertificate, SubContext.SIGNING_CERT));

		item = item.setNextItem(keyUsage(currentCertificate, SubContext.SIGNING_CERT));

		item = item.setNextItem(surname(currentCertificate, SubContext.SIGNING_CERT));

		item = item.setNextItem(givenName(currentCertificate, SubContext.SIGNING_CERT));

		item = item.setNextItem(commonName(currentCertificate, SubContext.SIGNING_CERT));

		item = item.setNextItem(pseudonym(currentCertificate, SubContext.SIGNING_CERT));

		item = item.setNextItem(country(currentCertificate, SubContext.SIGNING_CERT));

		item = item.setNextItem(organizationUnit(currentCertificate, SubContext.SIGNING_CERT));

		item = item.setNextItem(organizationName(currentCertificate, SubContext.SIGNING_CERT));

		item = item.setNextItem(certificateSignatureValid(currentCertificate, SubContext.SIGNING_CERT));

		item = item.setNextItem(certificateCryptographic(currentCertificate, context, SubContext.SIGNING_CERT));

		item = item.setNextItem(revocationDataAvailable(currentCertificate, SubContext.SIGNING_CERT));

		item = item.setNextItem(revocationDataTrusted(currentCertificate, SubContext.SIGNING_CERT));

		item = item.setNextItem(revocationFreshness(currentCertificate));

		item = item.setNextItem(certificateRevoked(currentCertificate, SubContext.SIGNING_CERT));

		item = item.setNextItem(certificateOnHold(currentCertificate, SubContext.SIGNING_CERT));

		item = item.setNextItem(signingCertificateInTSLValidity(currentCertificate));

		item = item.setNextItem(signingCertificateTSLStatus(currentCertificate));

		item = item.setNextItem(signingCertificateTSLStatusAndValidity(currentCertificate));

		// These constraints apply only to the main signature
		if (Context.SIGNATURE.equals(context)) {
			item = item.setNextItem(signingCertificateQualified(currentCertificate));

			item = item.setNextItem(signingCertificateSupportedBySSCD(currentCertificate));

			item = item.setNextItem(signingCertificateIssuedToLegalPerson(currentCertificate));
		}

		// check cryptographic constraints for the revocation token
		RevocationWrapper revocationData = currentCertificate.getRevocationData();
		if (revocationData != null) {
			item = item.setNextItem(revocationCryptographic(revocationData, Context.REVOCATION, SubContext.SIGNING_CERT));
		}

		// Check CA_CERTIFICATEs
		List<XmlChainCertificate> certificateChainList = currentCertificate.getCertificateChain();
		if (CollectionUtils.isNotEmpty(certificateChainList)) {
			for (XmlChainCertificate chainCertificate : certificateChainList) {
				CertificateWrapper certificate = diagnosticData.getUsedCertificateByIdNullSafe(chainCertificate.getId());

				item = item.setNextItem(certificateExpiration(certificate, SubContext.CA_CERTIFICATE));

				item = item.setNextItem(keyUsage(certificate, SubContext.CA_CERTIFICATE));

				item = item.setNextItem(surname(certificate, SubContext.CA_CERTIFICATE));

				item = item.setNextItem(givenName(certificate, SubContext.CA_CERTIFICATE));

				item = item.setNextItem(commonName(certificate, SubContext.CA_CERTIFICATE));

				item = item.setNextItem(pseudonym(certificate, SubContext.CA_CERTIFICATE));

				item = item.setNextItem(country(certificate, SubContext.CA_CERTIFICATE));

				item = item.setNextItem(organizationUnit(certificate, SubContext.CA_CERTIFICATE));

				item = item.setNextItem(organizationName(certificate, SubContext.CA_CERTIFICATE));

				item = item.setNextItem(certificateSignatureValid(certificate, SubContext.CA_CERTIFICATE));

				item = item.setNextItem(intermediateCertificateRevoked(certificate, SubContext.CA_CERTIFICATE));

				item = item.setNextItem(certificateCryptographic(certificate, context, SubContext.CA_CERTIFICATE));

				// check cryptographic constraints for the revocation token
				RevocationWrapper caRevocationData = certificate.getRevocationData();
				if (caRevocationData != null) {
					item = item.setNextItem(revocationCryptographic(caRevocationData, Context.REVOCATION, SubContext.CA_CERTIFICATE));
				}
			}
		}
	}

	private ChainItem<XmlXCV> prospectiveCertificateChain() {
		LevelConstraint constraint = validationPolicy.getProspectiveCertificateChainConstraint(context);
		return new ProspectiveCertificateChainCheck(result, currentCertificate, diagnosticData, constraint);
	}

	private ChainItem<XmlXCV> certificateExpiration(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateNotExpiredConstraint(context, subContext);
		return new CertificateExpirationCheck(result, certificate, currentTime, constraint);
	}

	private ChainItem<XmlXCV> keyUsage(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateKeyUsageConstraint(context, subContext);
		return new KeyUsageCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> surname(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateSurnameConstraint(context, subContext);
		return new SurnameCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> givenName(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateGivenNameConstraint(context, subContext);
		return new GivenNameCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> commonName(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateCommonNameConstraint(context, subContext);
		return new CommonNameCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> pseudonym(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificatePseudonymConstraint(context, subContext);
		return new PseudonymCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> country(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateCountryConstraint(context, subContext);
		return new CountryCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> organizationName(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateOrganizationNameConstraint(context, subContext);
		return new OrganizationNameCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> organizationUnit(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateOrganizationUnitConstraint(context, subContext);
		return new OrganizationUnitCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> certificateSignatureValid(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateSignatureConstraint(context, subContext);
		return new CertificateSignatureValidCheck<XmlXCV>(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> revocationDataAvailable(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getRevocationDataAvailableConstraint(context, subContext);
		return new RevocationDataAvailableCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> revocationDataTrusted(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getRevocationDataTrustedConstraint(context, subContext);
		return new RevocationDataTrustedCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> revocationFreshness(CertificateWrapper certificate) {
		TimeConstraint revocationFreshnessConstraints = validationPolicy.getRevocationFreshnessConstraint();
		return new RevocationFreshnessCheck(result, certificate, currentTime, revocationFreshnessConstraints);
	}

	private ChainItem<XmlXCV> certificateRevoked(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateNotRevokedConstraint(context, subContext);
		return new SigningCertificateRevokedCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> intermediateCertificateRevoked(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateNotRevokedConstraint(context, subContext);
		return new IntermediateCertificateRevokedCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> certificateOnHold(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateNotOnHoldConstraint(context, subContext);
		return new SigningCertificateOnHoldCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> signingCertificateInTSLValidity(CertificateWrapper certificate) {
		LevelConstraint constraint = validationPolicy.getSigningCertificateTSLValidityConstraint(context);
		return new SigningCertificateTSLValidityCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> signingCertificateTSLStatus(CertificateWrapper certificate) {
		LevelConstraint constraint = validationPolicy.getSigningCertificateTSLStatusConstraint(context);
		return new SigningCertificateTSLStatusCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> signingCertificateTSLStatusAndValidity(CertificateWrapper certificate) {
		LevelConstraint constraint = validationPolicy.getSigningCertificateTSLStatusAndValidityConstraint(context);
		return new SigningCertificateTSLStatusAndValidityCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> certificateCryptographic(CertificateWrapper certificate, Context context, SubContext subcontext) {
		CryptographicConstraint cryptographicConstraint = validationPolicy.getCertificateCryptographicConstraint(context, subcontext);
		return new CertificateCryptographicCheck(result, certificate, currentTime, cryptographicConstraint);
	}

	private ChainItem<XmlXCV> revocationCryptographic(RevocationWrapper revocationData, Context revocation, SubContext subcontext) {
		CryptographicConstraint cryptographicConstraint = validationPolicy.getCertificateCryptographicConstraint(context, subcontext);
		return new CryptographicCheck<XmlXCV>(result, revocationData, currentTime, cryptographicConstraint);
	}

	private ChainItem<XmlXCV> signingCertificateQualified(CertificateWrapper certificate) {
		LevelConstraint constraint = validationPolicy.getSigningCertificateQualificationConstraint(context);
		return new SigningCertificateQualifiedCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> signingCertificateSupportedBySSCD(CertificateWrapper certificate) {
		LevelConstraint constraint = validationPolicy.getSigningCertificateSupportedBySSCDConstraint(context);
		return new SigningCertificateSupportedBySSCDCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> signingCertificateIssuedToLegalPerson(CertificateWrapper certificate) {
		LevelConstraint constraint = validationPolicy.getSigningCertificateIssuedToLegalPersonConstraint(context);
		return new SigningCertificateIssuedToLegalPersonCheck(result, certificate, constraint);
	}

}
