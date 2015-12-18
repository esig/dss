package eu.europa.esig.dss.EN319102.bbb.xcv.checks;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.TSLConstant;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProviderType;
import eu.europa.esig.dss.validation.CertificateWrapper;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SigningCertificateTSLValidityCheck extends ChainItem<XmlXCV> {

	private final CertificateWrapper certificate;

	public SigningCertificateTSLValidityCheck(XmlXCV result, CertificateWrapper certificate, LevelConstraint constraint) {
		super(result, constraint);
		this.certificate = certificate;
	}

	@Override
	protected boolean process() {
		String trustedSource = certificate.getLastChainCertificateSource();
		if (CertificateSourceType.TRUSTED_STORE.name().equals(trustedSource)) {
			return true;
		}

		Date certificateValidFrom = certificate.getNotBefore();
		List<XmlTrustedServiceProviderType> tspList = certificate.getCertificateTSPService();
		boolean found = false;
		for (XmlTrustedServiceProviderType trustedServiceProvider : tspList) {
			String serviceTypeIdentifier = trustedServiceProvider.getTSPServiceType();
			if (!TSLConstant.CA_QC.equals(serviceTypeIdentifier)) {
				continue;
			}
			Date statusStartDate = trustedServiceProvider.getStartDate();
			Date statusEndDate = trustedServiceProvider.getEndDate();
			// The issuing time of the certificate should be into the validity period of the associated service
			if (certificateValidFrom.after(statusStartDate) && ((statusEndDate == null) || certificateValidFrom.before(statusEndDate))) {
				String status = trustedServiceProvider.getStatus();
				found = TSLStatusUtils.isUndersupervision(status) || TSLStatusUtils.isAccredited(status) || TSLStatusUtils.isSupervisionInCessation(status);
				if (found) {
					break;
				}
			}
		}
		return found;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.CTS_IIDOCWVPOTS;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.CTS_IIDOCWVPOTS_ANS;
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
