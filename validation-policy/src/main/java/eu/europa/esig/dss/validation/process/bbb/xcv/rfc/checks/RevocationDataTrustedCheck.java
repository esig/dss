package eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks;

import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.jaxb.detailedreport.XmlRFC;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class RevocationDataTrustedCheck extends ChainItem<XmlRFC> {

	private final RevocationWrapper revocationData;

	public RevocationDataTrustedCheck(XmlRFC result, RevocationWrapper revocationData, LevelConstraint constraint) {
		super(result, constraint);
		this.revocationData = revocationData;
	}

	@Override
	protected boolean process() {
		String anchorSource = null;
		if (revocationData != null) {
			anchorSource = revocationData.getLastChainCertificateSource();
		}
		CertificateSourceType anchorSourceType = StringUtils.isBlank(anchorSource) ? CertificateSourceType.UNKNOWN : CertificateSourceType
				.valueOf(anchorSource);
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
