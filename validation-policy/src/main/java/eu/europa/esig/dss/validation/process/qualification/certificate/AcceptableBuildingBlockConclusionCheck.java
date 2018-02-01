package eu.europa.esig.dss.validation.process.qualification.certificate;

import eu.europa.esig.dss.jaxb.detailedreport.XmlCertificate;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class AcceptableBuildingBlockConclusionCheck extends ChainItem<XmlCertificate> {

	private final XmlConclusion buildingBlockConclusion;

	public AcceptableBuildingBlockConclusionCheck(XmlCertificate result, XmlConclusion buildingBlockConclusion, LevelConstraint constraint) {
		super(result, constraint);

		this.buildingBlockConclusion = buildingBlockConclusion;
	}

	@Override
	protected boolean process() {
		return isValidConclusion(buildingBlockConclusion);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_ACCEPT;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_ACCEPT_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return buildingBlockConclusion.getIndication();
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return buildingBlockConclusion.getSubIndication();
	}

}
