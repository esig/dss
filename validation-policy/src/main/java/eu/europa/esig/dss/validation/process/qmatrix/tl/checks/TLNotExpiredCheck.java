package eu.europa.esig.dss.validation.process.qmatrix.tl.checks;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlTLAnalysis;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedList;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class TLNotExpiredCheck extends ChainItem<XmlTLAnalysis> {

	private final XmlTrustedList currentTL;
	private final Date currentTime;

	public TLNotExpiredCheck(XmlTLAnalysis result, XmlTrustedList currentTL, Date currentTime, LevelConstraint constraint) {
		super(result, constraint);
		this.currentTL = currentTL;
		this.currentTime = currentTime;
	}

	@Override
	protected boolean process() {
		Date nextUpdate = currentTL.getNextUpdate();
		if (nextUpdate != null && nextUpdate.after(currentTime)) {
			return true;
		}
		return false;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_TL_EXP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_TL_EXP_ANS;
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
