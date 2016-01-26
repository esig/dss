package eu.europa.esig.dss.validation.process.bbb.rfc.checks;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlRFC;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.RuleUtils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.jaxb.policy.TimeConstraint;

public class RevocationDataFreshCheck extends ChainItem<XmlRFC> {

	private final RevocationWrapper revocationData;
	private final Date validationDate;
	private final TimeConstraint timeConstraint;

	public RevocationDataFreshCheck(XmlRFC result, RevocationWrapper revocationData, Date validationDate, TimeConstraint constraint) {
		super(result, constraint);

		this.revocationData = revocationData;
		this.validationDate = validationDate;
		this.timeConstraint = constraint;
	}

	@Override
	protected boolean process() {
		if (revocationData != null) {
			long maxFreshness = getMaxFreshness();
			long validationDateTime = validationDate.getTime();
			long limit = validationDateTime - maxFreshness;

			Date productionDate = revocationData.getProductionDate();
			return productionDate != null && productionDate.after(new Date(limit));
		}
		return false;
	}

	private long getMaxFreshness() {
		long maxFreshness = RuleUtils.convertDuration(timeConstraint);
		if (maxFreshness == Integer.MAX_VALUE) {
			maxFreshness = diff(revocationData.getNextUpdate(), revocationData.getThisUpdate());
		}
		return maxFreshness;
	}

	private long diff(Date nextUpdate, Date thisUpdate) {
		long nextUpdateTime = nextUpdate == null ? 0 : nextUpdate.getTime();
		long thisUpdateTime = thisUpdate == null ? 0 : thisUpdate.getTime();
		return nextUpdateTime - thisUpdateTime;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_RFC_IRIF;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_RFC_IRIF_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INVALID;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return null;
	}

}
