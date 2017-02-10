package eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlPSV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class POEExistsCheck extends ChainItem<XmlPSV> {

	public POEExistsCheck(XmlPSV result, LevelConstraint constraint) {
		super(result, constraint);
	}

	@Override
	protected boolean process() {
		return true; // always true if the object is created
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.PSV_ITPOSVAOBCT;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return null;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return null;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return null;
	}

}
