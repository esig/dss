package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlFC;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class MimeTypeFilePresentCheck extends ChainItem<XmlFC> {

	private final boolean mimetypePresent;

	public MimeTypeFilePresentCheck(XmlFC result, boolean mimetypePresent, LevelConstraint constraint) {
		super(result, constraint);
		this.mimetypePresent = mimetypePresent;
	}

	@Override
	protected boolean process() {
		return mimetypePresent;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_FC_ITMFP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_FC_ITMFP_ANS;
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
