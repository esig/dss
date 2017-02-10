package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlFC;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class AcceptableZipCommentCheck extends AbstractMultiValuesCheckItem<XmlFC> {

	private final String zipComment;

	public AcceptableZipCommentCheck(XmlFC result, String zipComment, MultiValuesConstraint constraint) {
		super(result, constraint);
		this.zipComment = zipComment;
	}

	@Override
	protected boolean process() {
		return processValueCheck(zipComment);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_FC_ITEZCF;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_FC_ITEZCF_ANS;
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
