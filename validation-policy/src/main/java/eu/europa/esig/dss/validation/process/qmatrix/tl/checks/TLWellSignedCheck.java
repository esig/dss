package eu.europa.esig.dss.validation.process.qmatrix.tl.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlTLAnalysis;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedList;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class TLWellSignedCheck extends ChainItem<XmlTLAnalysis> {

	private final XmlTrustedList currentTL;

	public TLWellSignedCheck(XmlTLAnalysis result, XmlTrustedList currentTL, LevelConstraint constraint) {
		super(result, constraint);
		this.currentTL = currentTL;
	}

	@Override
	protected boolean process() {
		return currentTL.isWellSigned();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_TL_WS;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_TL_WS_ANS;
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
