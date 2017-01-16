package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import java.util.Date;
import java.util.Set;

import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class TimestampCoherenceOrderCheck extends ChainItem<XmlValidationProcessLongTermData> {

	private final Set<TimestampWrapper> timestamps;

	public TimestampCoherenceOrderCheck(XmlValidationProcessLongTermData result, Set<TimestampWrapper> timestamps, LevelConstraint constraint) {
		super(result, constraint);
		this.timestamps = timestamps;
	}

	@Override
	protected boolean process() {
		if (Utils.collectionSize(timestamps) <= 1) {
			return true;
		}

		Date latestContent = getLatestTimestampProductionDate(timestamps, TimestampType.CONTENT_TIMESTAMP, TimestampType.ALL_DATA_OBJECTS_TIMESTAMP,
				TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);

		Date earliestSignature = getEarliestTimestampProductionTime(timestamps, TimestampType.SIGNATURE_TIMESTAMP);
		Date latestSignature = getLatestTimestampProductionDate(timestamps, TimestampType.SIGNATURE_TIMESTAMP);

		Date earliestValidationData = getEarliestTimestampProductionTime(timestamps, TimestampType.VALIDATION_DATA_TIMESTAMP,
				TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
		Date latestValidationData = getLatestTimestampProductionDate(timestamps, TimestampType.VALIDATION_DATA_TIMESTAMP,
				TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);

		Date earliestArchive = getEarliestTimestampProductionTime(timestamps, TimestampType.ARCHIVE_TIMESTAMP);

		if ((latestContent == null) && (earliestSignature == null) && (earliestValidationData == null) && (earliestArchive == null)) {
			return true;
		}

		boolean ok = true;
		if ((earliestSignature == null) && ((earliestValidationData != null) || (earliestArchive != null))) {
			ok = false;
		}

		// Check content-timestamp against-signature timestamp
		if ((latestContent != null) && (earliestSignature != null)) {
			ok = ok && latestContent.before(earliestSignature);
		}

		// Check signature-timestamp against validation-data and validation-data-refs-only timestamp
		if ((latestSignature != null) && (earliestValidationData != null)) {
			ok = ok && latestSignature.before(earliestValidationData);
		}

		// Check archive-timestamp
		if ((latestSignature != null) && (earliestArchive != null)) {
			ok = ok && earliestArchive.after(latestSignature);
		}

		if ((latestValidationData != null) && (earliestArchive != null)) {
			ok = ok && earliestArchive.after(latestValidationData);
		}

		return ok;
	}

	private Date getLatestTimestampProductionDate(Set<TimestampWrapper> timestamps, TimestampType... selectedTimestampTypes) {
		Date latestProductionTime = null;
		for (TimestampWrapper timestamp : timestamps) {
			if (isInSelectedTypes(selectedTimestampTypes, timestamp.getType())) {
				Date productionTime = timestamp.getProductionTime();
				if ((latestProductionTime == null) || latestProductionTime.before(productionTime)) {
					latestProductionTime = productionTime;
				}
			}
		}
		return latestProductionTime;
	}

	private Date getEarliestTimestampProductionTime(Set<TimestampWrapper> timestamps, TimestampType... selectedTimestampTypes) {
		Date earliestProductionTime = null;
		for (TimestampWrapper timestamp : timestamps) {
			if (isInSelectedTypes(selectedTimestampTypes, timestamp.getType())) {
				Date productionTime = timestamp.getProductionTime();
				if ((earliestProductionTime == null) || earliestProductionTime.after(productionTime)) {
					earliestProductionTime = productionTime;
				}
			}
		}
		return earliestProductionTime;
	}

	private boolean isInSelectedTypes(TimestampType[] allowedTypes, String type) {
		for (TimestampType timestampType : allowedTypes) {
			if (timestampType.name().equals(type)) {
				return true;
			}
		}
		return false;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.TSV_ASTPTCT;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.TSV_ASTPTCT_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.TIMESTAMP_ORDER_FAILURE;
	}

}
