package eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks;

import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import eu.europa.esig.dss.detailedreport.jaxb.XmlRFC;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;

public abstract class AbstractRevocationFreshCheck extends ChainItem<XmlRFC> {

	protected final RevocationWrapper revocationData;
	private final Date validationDate;

	protected AbstractRevocationFreshCheck(XmlRFC result, RevocationWrapper revocationData, Date validationDate, LevelConstraint constraint) {
		super(result, constraint);
		this.revocationData = revocationData;
		this.validationDate = validationDate;
	}
	
	protected boolean isProductionDateNotBeforeValidationTime() {
		long maxFreshness = getMaxFreshness();
		long validationDateTime = validationDate.getTime();
		long limit = validationDateTime - maxFreshness;

		Date productionDate = revocationData.getProductionDate();
		return productionDate != null && productionDate.after(new Date(limit));
	}

	protected abstract long getMaxFreshness();

	@Override
	protected String getAdditionalInfo() {
		String productionTimeString = "not defined";
		String nextUpdateString = "not defined";
		if (revocationData != null) {
			if (revocationData.getProductionDate() != null)
				productionTimeString = convertDate(revocationData.getProductionDate());
			if (revocationData.getNextUpdate() != null)
				nextUpdateString = convertDate(revocationData.getNextUpdate());
		}
		Object[] params = new Object[] { convertDate(validationDate), productionTimeString, nextUpdateString };
		return MessageFormat.format(AdditionalInfo.REVOCATION_CHECK, params);
	}
	
	private String convertDate(Date date) {
		SimpleDateFormat sdf = new SimpleDateFormat(AdditionalInfo.DATE_FORMAT);
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		return sdf.format(date);
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