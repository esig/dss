package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.wrappers.TimestampWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class TimestampMessageImprintDataFoundCheck extends ChainItem<XmlSAV> {

	private final TimestampWrapper timestamp;

	public TimestampMessageImprintDataFoundCheck(XmlSAV result, TimestampWrapper timestamp, LevelConstraint constraint) {
		super(result, constraint);
		this.timestamp = timestamp;
	}

	@Override
	protected boolean process() {
		return timestamp.isMessageImprintDataFound();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ADEST_IMIDF;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ADEST_IMIDF_ANS;
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
