package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.wrappers.CertificateWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class RevocationDataAvailableCheck extends ChainItem<XmlXCV> {

	private final CertificateWrapper certificate;

	public RevocationDataAvailableCheck(XmlXCV result, CertificateWrapper certificate, LevelConstraint constraint) {
		super(result, constraint);
		this.certificate = certificate;
	}

	@Override
	protected boolean process() {
		return certificate.isRevocationDataAvailable();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_IRDPFC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_IRDPFC_ANS;
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