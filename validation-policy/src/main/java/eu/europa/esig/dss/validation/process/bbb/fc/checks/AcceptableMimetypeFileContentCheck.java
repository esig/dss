package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlFC;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class AcceptableMimetypeFileContentCheck extends AbstractMultiValuesCheckItem<XmlFC> {

	private final String mimetypeFileContent;

	public AcceptableMimetypeFileContentCheck(XmlFC result, String mimetypeFileContent, MultiValuesConstraint constraint) {
		super(result, constraint);
		this.mimetypeFileContent = mimetypeFileContent;
	}

	@Override
	protected boolean process() {
		return processValueCheck(mimetypeFileContent);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_FC_IEMCF;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_FC_IEMCF_ANS;
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
