package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class TimestampMessageImprintDataIntactCheck extends ChainItem<XmlSAV> {

	private final TimestampWrapper timestamp;

	public TimestampMessageImprintDataIntactCheck(XmlSAV result, TimestampWrapper timestamp, LevelConstraint constraint) {
		super(result, constraint);
		this.timestamp = timestamp;
	}

	@Override
	protected boolean process() {
		return timestamp.isMessageImprintDataIntact();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ADEST_IMIVC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ADEST_IMIVC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INVALID;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIG_CONSTRAINTS_FAILURE;
	}

}
