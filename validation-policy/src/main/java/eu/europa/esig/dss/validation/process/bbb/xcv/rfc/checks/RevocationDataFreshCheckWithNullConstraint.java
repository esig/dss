package eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks;

import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlRFC;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class RevocationDataFreshCheckWithNullConstraint extends ChainItem<XmlRFC> {

	private final RevocationWrapper revocationData;
	private final Date validationDate;

	public RevocationDataFreshCheckWithNullConstraint(XmlRFC result, RevocationWrapper revocationData,
			Date validationDate, LevelConstraint constraint) {
		super(result, constraint);

		this.revocationData = revocationData;
		this.validationDate = validationDate;
	}

	@Override
	protected boolean process() {
		if (revocationData != null && revocationData.getNextUpdate() != null) {
			long maxFreshness = getMaxFreshness();
			long validationDateTime = validationDate.getTime();
			long limit = validationDateTime - maxFreshness;

			Date productionDate = revocationData.getProductionDate();
			return productionDate != null && productionDate.after(new Date(limit));
		}
		return false;
	}

	private long getMaxFreshness() {
		return diff(revocationData.getNextUpdate(), revocationData.getThisUpdate());
	}

	private long diff(Date nextUpdate, Date thisUpdate) {
		long nextUpdateTime = nextUpdate == null ? 0 : nextUpdate.getTime();
		long thisUpdateTime = thisUpdate == null ? 0 : thisUpdate.getTime();
		return nextUpdateTime - thisUpdateTime;
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
