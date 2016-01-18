package eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks.pcv.checks;

import eu.europa.esig.dss.MessageTag;
import eu.europa.esig.dss.EN319102.validation.ChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlPCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlVTS;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ValidationTimeSlidingCheck extends ChainItem<XmlPCV> {

	private final XmlVTS vts;

	public ValidationTimeSlidingCheck(XmlPCV result, XmlVTS vts, LevelConstraint constraint) {
		super(result, constraint);

		this.vts = vts;
	}

	@Override
	protected boolean process() {
		return vts != null && vts.getConclusion() != null && Indication.VALID.equals(vts.getConclusion().getIndication());
	}

	@Override
	protected MessageTag getMessageTag() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		// TODO Auto-generated method stub
		return null;
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
