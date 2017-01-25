package eu.europa.esig.dss.validation.process.vpfswatsp.checks.pcv.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlPCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlVTS;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ValidationTimeSlidingCheck extends ChainItem<XmlPCV> {

	private final XmlVTS vts;

	public ValidationTimeSlidingCheck(XmlPCV result, XmlVTS vts, LevelConstraint constraint) {
		super(result, constraint);

		this.vts = vts;
	}

	@Override
	protected boolean process() {
		return isValid(vts);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.PCV_IVTSC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.PCV_IVTSC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return vts.getConclusion().getIndication();
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return vts.getConclusion().getSubIndication();
	}

}
