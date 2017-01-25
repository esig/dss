package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlFC;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class ContainerTypeCheck extends AbstractMultiValuesCheckItem<XmlFC> {

	private final String containerType;

	public ContainerTypeCheck(XmlFC result, String containerType, MultiValuesConstraint constraint) {
		super(result, constraint);
		this.containerType = containerType;
	}

	@Override
	protected boolean process() {
		return processValueCheck(containerType);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_FC_IECTF;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_FC_IECTF_ANS;
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
