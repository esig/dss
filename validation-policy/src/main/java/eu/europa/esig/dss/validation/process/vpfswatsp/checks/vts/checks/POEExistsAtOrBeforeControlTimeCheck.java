package eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlVTS;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class POEExistsAtOrBeforeControlTimeCheck extends ChainItem<XmlVTS> {

	private final String poeId;
	private final Date controlTime;
	private final POEExtraction poe;

	public POEExistsAtOrBeforeControlTimeCheck(XmlVTS result, String poeId, Date controlTime, POEExtraction poe, LevelConstraint constraint) {
		super(result, constraint);

		this.poeId = poeId;
		this.controlTime = controlTime;
		this.poe = poe;
	}

	@Override
	protected boolean process() {
		return poe.isPOEExists(poeId, controlTime);
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
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NO_POE;
	}

}
