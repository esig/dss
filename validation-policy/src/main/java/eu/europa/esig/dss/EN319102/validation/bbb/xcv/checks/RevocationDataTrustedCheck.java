package eu.europa.esig.dss.EN319102.validation.bbb.xcv.checks;

import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.MessageTag;
import eu.europa.esig.dss.EN319102.validation.ChainItem;
import eu.europa.esig.dss.EN319102.wrappers.CertificateWrapper;
import eu.europa.esig.dss.EN319102.wrappers.RevocationWrapper;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class RevocationDataTrustedCheck extends ChainItem<XmlXCV> {

	private final CertificateWrapper certificate;

	public RevocationDataTrustedCheck(XmlXCV result, CertificateWrapper certificate, LevelConstraint constraint) {
		super(result, constraint);
		this.certificate = certificate;
	}

	@Override
	protected boolean process() {
		String anchorSource = null;
		RevocationWrapper revocationData = certificate.getRevocationData();
		if (revocationData != null) {
			anchorSource = revocationData.getLastChainCertificateSource();
		}
		CertificateSourceType anchorSourceType = StringUtils.isBlank(anchorSource) ? CertificateSourceType.UNKNOWN
				: CertificateSourceType.valueOf(anchorSource);
		return CertificateSourceType.TRUSTED_LIST.equals(anchorSourceType) || CertificateSourceType.TRUSTED_STORE.equals(anchorSourceType);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_IRDTFC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_IRDTFC_ANS;
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
