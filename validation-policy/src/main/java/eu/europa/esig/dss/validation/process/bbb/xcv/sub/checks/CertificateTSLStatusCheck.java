package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProviderType;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateTSLStatusCheck extends ChainItem<XmlSubXCV> {

	private final CertificateWrapper certificate;

	public CertificateTSLStatusCheck(XmlSubXCV result, CertificateWrapper certificate, LevelConstraint constraint) {
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
			acceptableStatus = TSLStatusUtils.isUndersupervision(status) || TSLStatusUtils.isAccredited(status)
					|| TSLStatusUtils.isSupervisionInCessation(status);
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
