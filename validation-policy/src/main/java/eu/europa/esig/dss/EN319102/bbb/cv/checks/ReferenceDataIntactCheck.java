package eu.europa.esig.dss.EN319102.bbb.cv.checks;

import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.validation.TokenProxy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ReferenceDataIntactCheck extends ChainItem<XmlCV> {

	private final TokenProxy token;

	public ReferenceDataIntactCheck(XmlCV result, TokenProxy token, LevelConstraint constraint) {
		super(result, constraint);
		this.token = token;
	}

	@Override
	protected boolean process() {
		return token.isReferenceDataIntact();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_CV_IRDOI;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_CV_IRDOI_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INVALID;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.HASH_FAILURE;
	}

}
