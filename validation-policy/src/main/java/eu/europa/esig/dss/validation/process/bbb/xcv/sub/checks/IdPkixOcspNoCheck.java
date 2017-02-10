package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class IdPkixOcspNoCheck extends ChainItem<XmlSubXCV> {

	public IdPkixOcspNoCheck(XmlSubXCV result, LevelConstraint constraint) {
		super(result, constraint);
	}

	@Override
	protected boolean process() {
		// always true (information)
		return true;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_OCSP_NO_CHECK;
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
