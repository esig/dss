package eu.europa.esig.dss.EN319102.bbb.xcv.checks;

import java.util.List;

import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProviderType;
import eu.europa.esig.dss.validation.CertificateWrapper;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SigningCertificateTSLStatusCheck extends ChainItem<XmlXCV> {

	private final CertificateWrapper certificate;

	public SigningCertificateTSLStatusCheck(XmlXCV result, CertificateWrapper certificate, LevelConstraint constraint) {
		super(result, constraint);
		this.certificate = certificate;
	}

	@Override
	protected boolean process() {
		String trustedSource = certificate.getLastChainCertificateSource();
		if (CertificateSourceType.TRUSTED_STORE.name().equals(trustedSource)) {
			return true;
		}

		List<XmlTrustedServiceProviderType> tspList = certificate.getCertificateTSPService();
		boolean acceptableStatus = false;
		for (XmlTrustedServiceProviderType trustedServiceProvider : tspList) {
			String status = trustedServiceProvider.getStatus();
			acceptableStatus = TSLStatusUtils.isUndersupervision(status) || TSLStatusUtils.isAccredited(status) || TSLStatusUtils.isSupervisionInCessation(status);
			if (acceptableStatus) {
				break;
			}
		}

		return acceptableStatus;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.CTS_WITSS;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.CTS_WITSS_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.TRY_LATER;
	}

}
