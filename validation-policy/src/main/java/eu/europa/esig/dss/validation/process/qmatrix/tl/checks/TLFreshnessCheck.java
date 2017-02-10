package eu.europa.esig.dss.validation.process.qmatrix.tl.checks;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlTLAnalysis;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedList;
import eu.europa.esig.dss.validation.policy.RuleUtils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.TimeConstraint;

public class TLFreshnessCheck extends ChainItem<XmlTLAnalysis> {

	private final XmlTrustedList currentTL;
	private final Date currentTime;
	private final TimeConstraint timeConstraint;

	public TLFreshnessCheck(XmlTLAnalysis result, XmlTrustedList currentTL, Date currentTime, TimeConstraint timeConstraint) {
		super(result, timeConstraint);
		this.currentTL = currentTL;
		this.currentTime = currentTime;
		this.timeConstraint = timeConstraint;
	}

	@Override
	protected boolean process() {
		long maxFreshness = getMaxFreshness();
		long validationDateTime = currentTime.getTime();
		long limit = validationDateTime - maxFreshness;

		Date lastLoading = currentTL.getLastLoading();
		return lastLoading != null && lastLoading.after(new Date(limit));
	}

	private long getMaxFreshness() {
		return RuleUtils.convertDuration(timeConstraint);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_TL_FRESH;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_TL_FRESH_ANS;
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
