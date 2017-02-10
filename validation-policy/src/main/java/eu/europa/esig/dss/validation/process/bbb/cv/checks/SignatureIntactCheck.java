package eu.europa.esig.dss.validation.process.bbb.cv.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.TokenProxy;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SignatureIntactCheck extends ChainItem<XmlCV> {

	private final TokenProxy token;

	public SignatureIntactCheck(XmlCV result, TokenProxy token, LevelConstraint constraint) {
		super(result, constraint);
		this.token = token;
	}

	@Override
	protected boolean process() {
		return token.isSignatureIntact();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_CV_ISI;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_CV_ISI_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIG_CRYPTO_FAILURE;
	}

}
