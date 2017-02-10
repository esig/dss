package eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks;

import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlRFC;
import eu.europa.esig.dss.validation.policy.RuleUtils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.jaxb.policy.TimeConstraint;

public class RevocationDataFreshCheck extends ChainItem<XmlRFC> {

	private final RevocationWrapper revocationData;
	private final Date validationDate;
	private final TimeConstraint timeConstraint;

	public RevocationDataFreshCheck(XmlRFC result, RevocationWrapper revocationData, Date validationDate,
			TimeConstraint constraint) {
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
		return RuleUtils.convertDuration(timeConstraint);
	}

	@Override
	protected String getAdditionalInfo() {
		SimpleDateFormat sdf = new SimpleDateFormat(AdditionalInfo.DATE_FORMAT);
		String nextUpdateString = "not defined";
		if (revocationData != null && revocationData.getNextUpdate() != null) {
			nextUpdateString = sdf.format(revocationData.getNextUpdate());
		}
		Object[] params = new Object[] { nextUpdateString };
		return MessageFormat.format(AdditionalInfo.NEXT_UPDATE, params);
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
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.TRY_LATER;
	}

}
