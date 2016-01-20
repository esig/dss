package eu.europa.esig.dss.validation.process.bbb.xcv;

import java.util.Date;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainCertificate;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy.SubContext;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.CertificateExpirationCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.CertificateSignatureValidCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.IntermediateCertificateRevokedCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.KeyUsageCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.ProspectiveCertificateChainCheck;
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
import eu.europa.esig.dss.validation.wrappers.CertificateWrapper;
import eu.europa.esig.dss.validation.wrappers.DiagnosticData;
import eu.europa.esig.dss.validation.wrappers.RevocationWrapper;
import eu.europa.esig.dss.validation.wrappers.TokenProxy;
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

		List<XmlChainCertificate> certificateChainList = currentCertificate.getCertificateChain();

		if (CollectionUtils.isNotEmpty(certificateChainList)) {
			for (XmlChainCertificate chainCertificate : certificateChainList) {
				CertificateWrapper certificate = diagnosticData.getUsedCertificateByIdNullSafe(chainCertificate.getId());

				// Trusted certificated doesn't need validation
				// if (certificate.isTrusted()) {
				// continue;
				// }

				SubContext currentSubContext = SubContext.SIGNING_CERT;
				if (!StringUtils.equals(currentCertificate.getId(), certificate.getId())) { // CA
					currentSubContext = SubContext.CA_CERTIFICATE;
				}

				item = item.setNextItem(certificateExpiration(certificate, currentSubContext));

				item = item.setNextItem(keyUsage(certificate, currentSubContext));

				item = item.setNextItem(certificateSignatureValid(certificate, currentSubContext));

				if (SubContext.SIGNING_CERT.equals(currentSubContext)) {

					item = item.setNextItem(revocationDataAvailable(certificate, currentSubContext));

					item = item.setNextItem(revocationDataTrusted(certificate, currentSubContext));

					item = item.setNextItem(revocationFreshness(certificate));

					item = item.setNextItem(signingCertificateRevoked(certificate, currentSubContext));

					item = item.setNextItem(signingCertificateOnHold(certificate, currentSubContext));

					item = item.setNextItem(signingCertificateInTSLValidity(certificate));

					item = item.setNextItem(signingCertificateTSLStatus(certificate));

					item = item.setNextItem(signingCertificateTSLStatusAndValidity(certificate));

				} else {

					item = item.setNextItem(intermediateCertificateRevoked(certificate, currentSubContext));

				}

				// check cryptographic constraints for the revocation token
				RevocationWrapper revocationData = certificate.getRevocationData();
				if (revocationData != null) {
					item = item.setNextItem(certificateCryptographic(revocationData, Context.REVOCATION, currentSubContext));
				}

			}
		}

		// These constraints apply only to the main signature
		if (Context.SIGNATURE.equals(context)) {
			item = item.setNextItem(signingCertificateQualified(currentCertificate));

			item = item.setNextItem(signingCertificateSupportedBySSCD(currentCertificate));

			item = item.setNextItem(signingCertificateIssuedToLegalPerson(currentCertificate));
		}

		if (CollectionUtils.isNotEmpty(certificateChainList)) {
			String lastChainCertId = currentCertificate.getLastChainCertificateId();
			for (XmlChainCertificate chainCertificate : certificateChainList) {
				CertificateWrapper chainItem = diagnosticData.getUsedCertificateByIdNullSafe(chainCertificate.getId());

				/**
				 * The trusted anchor is not checked. In the case of a
				 * certificate chain consisting of a single certificate which is
				 * trusted we need to set this variable to true.
				 */
				if (StringUtils.equals(lastChainCertId, chainCertificate.getId()) && chainItem.isTrusted()) {
					continue;
				}

				SubContext currentSubContext = StringUtils.equals(chainItem.getId(), currentCertificate.getId()) ? SubContext.SIGNING_CERT
						: SubContext.CA_CERTIFICATE;
				item = item.setNextItem(certificateCryptographic(chainItem, context, currentSubContext));
			}
		}
	}

	private ChainItem<XmlXCV> prospectiveCertificateChain() {
		LevelConstraint constraint = validationPolicy.getProspectiveCertificateChainConstraint(context);
		return new ProspectiveCertificateChainCheck(result, currentCertificate, diagnosticData, constraint);
	}

	private ChainItem<XmlXCV> certificateExpiration(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getSigningCertificateExpirationConstraint(context, subContext);
		return new CertificateExpirationCheck(result, certificate, currentTime, constraint);
	}

	private ChainItem<XmlXCV> keyUsage(CertificateWrapper certificate, SubContext subContext) {
		MultiValuesConstraint constraint = validationPolicy.getSigningCertificateKeyUsageConstraint(context, subContext);
		return new KeyUsageCheck(result, certificate, constraint);
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
		LevelConstraint constraint = validationPolicy.getRevocationDataIsTrustedConstraint(context, subContext);
		return new RevocationDataTrustedCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> revocationFreshness(CertificateWrapper certificate) {
		TimeConstraint revocationFreshnessConstraints = validationPolicy.getRevocationFreshnessConstraint();
		return new RevocationFreshnessCheck(result, certificate, currentTime, revocationFreshnessConstraints);
	}

	private ChainItem<XmlXCV> signingCertificateRevoked(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateRevokedConstraint(context, subContext);
		return new SigningCertificateRevokedCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> intermediateCertificateRevoked(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getCertificateRevokedConstraint(context, subContext);
		return new IntermediateCertificateRevokedCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> signingCertificateOnHold(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getSigningCertificateOnHoldConstraint(context, subContext);
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

	private ChainItem<XmlXCV> certificateCryptographic(TokenProxy token, Context context, SubContext subcontext) {
		CryptographicConstraint cryptographicConstraint = validationPolicy.getCertificateCryptographicConstraint(context, subcontext);
		return new CryptographicCheck<XmlXCV>(result, token, currentTime, cryptographicConstraint);
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
