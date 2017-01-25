package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlRFC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.SubContext;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.RevocationFreshnessChecker;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.AuthorityInfoAccessPresentCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateCryptographicCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateExpirationCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateIssuedToLegalPersonCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateIssuedToNaturalPersonCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateOnHoldCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificatePolicyIdsCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateQCStatementIdsCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateQualifiedCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateRevokedCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateSignatureValidCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateSupportedByQSCDCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CommonNameCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CountryCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.GivenNameCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.IdPkixOcspNoCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.KeyUsageCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.OrganizationNameCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.OrganizationUnitCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.PseudoUsageCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.PseudonymCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationFreshnessCheckerResult;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationInfoAccessPresentCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.SerialNumberCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.SurnameCheck;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;
import eu.europa.esig.jaxb.policy.LevelConstraint;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class SubX509CertificateValidation extends Chain<XmlSubXCV> {

	private final CertificateWrapper currentCertificate;
	private final Date currentTime;

	private final Context context;
	private final SubContext subContext;
	private final ValidationPolicy validationPolicy;

	public SubX509CertificateValidation(CertificateWrapper currentCertificate, Date currentTime, Context context, SubContext subContext,
			ValidationPolicy validationPolicy) {
		super(new XmlSubXCV());

		result.setId(currentCertificate.getId());
		result.setTrustAnchor(currentCertificate.isTrusted());

		this.currentCertificate = currentCertificate;
		this.currentTime = currentTime;

		this.context = context;
		this.subContext = subContext;
		this.validationPolicy = validationPolicy;
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

		item = item.setNextItem(pseudonym(currentCertificate, subContext));

		item = item.setNextItem(country(currentCertificate, subContext));

		item = item.setNextItem(organizationUnit(currentCertificate, subContext));

		item = item.setNextItem(organizationName(currentCertificate, subContext));

		item = item.setNextItem(certificateSignatureValid(currentCertificate, subContext));

		item = item.setNextItem(certificateCryptographic(currentCertificate, context, subContext));

		item = item.setNextItem(keyUsage(currentCertificate, subContext));

		item = item.setNextItem(aiaPresent(currentCertificate, subContext));

		item = item.setNextItem(revocationInfoAccessPresent(currentCertificate, subContext));

		item = item.setNextItem(certificateRevoked(currentCertificate, subContext));

		item = item.setNextItem(certificateOnHold(currentCertificate, subContext));

		item = item.setNextItem(certificateExpiration(currentCertificate, subContext));

		item = item.setNextItem(certificatePolicyIds(currentCertificate, subContext));

		item = item.setNextItem(certificateQCStatementIds(currentCertificate, subContext));

		item = item.setNextItem(certificateQualified(currentCertificate, subContext));

		item = item.setNextItem(certificateSupportedByQSCD(currentCertificate, subContext));

		item = item.setNextItem(pseudoUsage(currentCertificate, subContext));

		item = item.setNextItem(certificateIssuedToLegalPerson(currentCertificate, subContext));

		item = item.setNextItem(certificateIssuedToNaturalPerson(currentCertificate, subContext));

		if (!isRevocationNoNeedCheck(currentCertificate)) {
			RevocationFreshnessChecker rfc = new RevocationFreshnessChecker(currentCertificate.getLatestRevocationData(), currentTime, context, subContext,
					validationPolicy);
			XmlRFC rfcResult = rfc.execute();
			result.setRFC(rfcResult);

			item = item.setNextItem(checkRevocationFreshnessCheckerResult(rfcResult));
		} else {
			item = item.setNextItem(idPkixOcspNoCheck());
		}
	}

	/*
	 * A signing certificate includes the id-pkix-ocsp-nocheck extension. This extension informs the OCSP client that
	 * the OCSP signing certificate should not be checked for revocation during the lifetime of the certificate. The
	 * OCSP Signing certificate should therefore have a short lifetime.
	 */
	private boolean isRevocationNoNeedCheck(CertificateWrapper certificate) {
		if (certificate.isIdPkixOcspNoCheck()) {
			return currentTime.compareTo(certificate.getNotBefore()) >= 0 && currentTime.compareTo(certificate.getNotAfter()) <= 0;
		}
		return false;
	}

	private ChainItem<XmlSubXCV> certificateExpiration(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateNotExpiredConstraint(context, subContext);
		return new CertificateExpirationCheck(result, certificate, currentTime, constraint);
	}

	private ChainItem<XmlSubXCV> keyUsage(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateKeyUsageConstraint(context, subContext);
		return new KeyUsageCheck(result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> aiaPresent(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateAuthorityInfoAccessPresentConstraint(context, subContext);
		return new AuthorityInfoAccessPresentCheck(result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> revocationInfoAccessPresent(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateRevocationInfoAccessPresentConstraint(context, subContext);
		return new RevocationInfoAccessPresentCheck(result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> surname(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateSurnameConstraint(context, subContext);
		return new SurnameCheck(result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> givenName(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateGivenNameConstraint(context, subContext);
		return new GivenNameCheck(result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> commonName(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateCommonNameConstraint(context, subContext);
		return new CommonNameCheck(result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> pseudonym(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificatePseudonymConstraint(context, subContext);
		return new PseudonymCheck(result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> country(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateCountryConstraint(context, subContext);
		return new CountryCheck(result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> organizationName(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateOrganizationNameConstraint(context, subContext);
		return new OrganizationNameCheck(result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> organizationUnit(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateOrganizationUnitConstraint(context, subContext);
		return new OrganizationUnitCheck(result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> serialNumber(CertificateWrapper signingCertificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateSerialNumberConstraint(context, subContext);
		return new SerialNumberCheck(result, signingCertificate, constraint);
	}

	private ChainItem<XmlSubXCV> pseudoUsage(CertificateWrapper signingCertificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificatePseudoUsageConstraint(context, subContext);
		return new PseudoUsageCheck(result, signingCertificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateSignatureValid(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateSignatureConstraint(context, subContext);
		return new CertificateSignatureValidCheck<XmlSubXCV>(result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateRevoked(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateNotRevokedConstraint(context, subContext);
		return new CertificateRevokedCheck(result, certificate, constraint, subContext);
	}

	private ChainItem<XmlSubXCV> certificateOnHold(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateNotOnHoldConstraint(context, subContext);
		return new CertificateOnHoldCheck(result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificatePolicyIds(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificatePolicyIdsConstraint(context, subContext);
		return new CertificatePolicyIdsCheck(result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateQCStatementIds(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getCertificateQCStatementIdsConstraint(context, subContext);
		return new CertificateQCStatementIdsCheck(result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateCryptographic(CertificateWrapper certificate, Context context, SubContext subcontext) {
		CryptographicConstraint cryptographicConstraint = validationPolicy.getCertificateCryptographicConstraint(context, subcontext);
		return new CertificateCryptographicCheck(result, certificate, currentTime, cryptographicConstraint);
	}

	private ChainItem<XmlSubXCV> certificateQualified(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateQualificationConstraint(context, subContext);
		return new CertificateQualifiedCheck(result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateSupportedByQSCD(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateSupportedByQSCDConstraint(context, subContext);
		return new CertificateSupportedByQSCDCheck(result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateIssuedToLegalPerson(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateIssuedToLegalPersonConstraint(context, subContext);
		return new CertificateIssuedToLegalPersonCheck(result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> certificateIssuedToNaturalPerson(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateIssuedToNaturalPersonConstraint(context, subContext);
		return new CertificateIssuedToNaturalPersonCheck(result, certificate, constraint);
	}

	private ChainItem<XmlSubXCV> checkRevocationFreshnessCheckerResult(XmlRFC rfcResult) {
		return new RevocationFreshnessCheckerResult(result, rfcResult, getFailLevelConstraint());
	}

	private ChainItem<XmlSubXCV> idPkixOcspNoCheck() {
		return new IdPkixOcspNoCheck(result, getFailLevelConstraint());
	}

}
