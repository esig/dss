package eu.europa.esig.dss.EN319102.bbb.xcv;

import java.util.Date;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.EN319102.bbb.AbstractBasicBuildingBlock;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.bbb.xcv.checks.CertificateExpirationCheck;
import eu.europa.esig.dss.EN319102.bbb.xcv.checks.CertificateSignatureValidCheck;
import eu.europa.esig.dss.EN319102.bbb.xcv.checks.KeyUsageCheck;
import eu.europa.esig.dss.EN319102.bbb.xcv.checks.ProspectiveCertificateChainCheck;
import eu.europa.esig.dss.EN319102.bbb.xcv.checks.RevocationDataAvailableCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainCertificate;
import eu.europa.esig.dss.validation.CertificateWrapper;
import eu.europa.esig.dss.validation.policy.ValidationPolicy2;
import eu.europa.esig.dss.validation.policy.ValidationPolicy2.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy2.SubContext;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.jaxb.policy.LevelConstraint;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

/**
 * 5.2.6 X.509 certificate validation
 * This building block validates the signing certificate at current time.
 */
public class X509CertificateValidation extends AbstractBasicBuildingBlock<XmlXCV> {

	private final DiagnosticData diagnosticData;
	private final CertificateWrapper currentCertificate;
	private final Date currentTime;

	private final ValidationPolicy2 validationPolicy;

	private ChainItem<XmlXCV> firstItem;
	private XmlXCV result = new XmlXCV();

	public X509CertificateValidation(DiagnosticData diagnosticData, CertificateWrapper currentCertificate, Date currentTime, ValidationPolicy2 validationPolicy) {
		this.diagnosticData = diagnosticData;
		this.currentCertificate = currentCertificate;
		this.currentTime = currentTime;
		this.validationPolicy = validationPolicy;
	}

	@Override
	public void initChain() {
		ChainItem<XmlXCV> item = firstItem = certificateExpiration(currentCertificate, SubContext.SIGNING_CERT);
		item = item.setNextItem(prospectiveCertificateChain());

		List<XmlChainCertificate> certificateChainList = currentCertificate.getCertificateChain();

		if (CollectionUtils.isNotEmpty(certificateChainList)) {
			for (XmlChainCertificate chainCertificate : certificateChainList) {
				CertificateWrapper certificate = diagnosticData.getUsedCertificateByIdNullSafe(chainCertificate.getId());

				SubContext currentSubContext = SubContext.SIGNING_CERT;

				if (!StringUtils.equals(currentCertificate.getId(), certificate.getId())) { // CA Certificate
					currentSubContext = SubContext.CA_CERTIFICATE;
					item = item.setNextItem(certificateExpiration(certificate, currentSubContext));
				}

				item = item.setNextItem(keyUsage(certificate, currentSubContext));

				item = item.setNextItem(certificateSignatureValid(certificate, currentSubContext));

				item = item.setNextItem(revocationDataAvailable(certificate, currentSubContext));

			}
		}
	}

	private ChainItem<XmlXCV> prospectiveCertificateChain() {
		LevelConstraint constraint = validationPolicy.getProspectiveCertificateChainConstraint(Context.MAIN_SIGNATURE);
		return new ProspectiveCertificateChainCheck(result, currentCertificate, diagnosticData, constraint);
	}

	private ChainItem<XmlXCV> certificateExpiration(CertificateWrapper certificate, SubContext subcontext) {
		LevelConstraint constraint = validationPolicy.getSigningCertificateExpirationConstraint(Context.MAIN_SIGNATURE, subcontext);
		return new CertificateExpirationCheck(result, certificate, currentTime, constraint);
	}

	private ChainItem<XmlXCV> keyUsage(CertificateWrapper certificate, SubContext currentSubContext) {
		// TODO multi context
		MultiValuesConstraint constraint = validationPolicy.getSigningCertificateKeyUsageConstraint(Context.MAIN_SIGNATURE);
		return new KeyUsageCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> certificateSignatureValid(CertificateWrapper certificate, SubContext subcontext) {
		LevelConstraint constraint = validationPolicy.getCertificateSignatureConstraint(Context.MAIN_SIGNATURE, subcontext);
		return new CertificateSignatureValidCheck(result, certificate, constraint);
	}

	private ChainItem<XmlXCV> revocationDataAvailable(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = validationPolicy.getRevocationDataAvailableConstraint(Context.MAIN_SIGNATURE, subContext);
		return new RevocationDataAvailableCheck(result, certificate, constraint);
	}

	@Override
	public XmlXCV execute() {
		firstItem.execute();
		return result;
	}

}
