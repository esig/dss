package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlFC;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ZipCommentPresentCheck extends ChainItem<XmlFC> {

	private final String zipComment;

	public ZipCommentPresentCheck(XmlFC result, String zipComment, LevelConstraint constraint) {
		super(result, constraint);
		this.zipComment = zipComment;
	}

	@Override
	protected boolean process() {
		return Utils.isStringNotBlank(zipComment);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_FC_ITZCP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_FC_ITZCP_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return null;
	}

}
