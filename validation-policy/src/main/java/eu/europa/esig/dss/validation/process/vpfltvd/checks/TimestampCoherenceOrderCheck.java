/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;

public class TimestampCoherenceOrderCheck extends ChainItem<XmlValidationProcessLongTermData> {

	private final List<TimestampWrapper> timestamps;

	public TimestampCoherenceOrderCheck(XmlValidationProcessLongTermData result, List<TimestampWrapper> timestamps, LevelConstraint constraint) {
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
			ok = ok && !latestContent.after(earliestSignature); // before or equals
		}

		// Check signature-timestamp against validation-data and validation-data-refs-only timestamp
		if ((latestSignature != null) && (earliestValidationData != null)) {
			ok = ok && !latestSignature.after(earliestValidationData);
		}

		// Check archive-timestamp
		if ((latestSignature != null) && (earliestArchive != null)) {
			ok = ok && !earliestArchive.before(latestSignature); // after or equals
		}

		if ((latestValidationData != null) && (earliestArchive != null)) {
			ok = ok && !earliestArchive.before(latestValidationData);
		}

		return ok;
	}

	private Date getLatestTimestampProductionDate(List<TimestampWrapper> timestamps, TimestampType... selectedTimestampTypes) {
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

	private Date getEarliestTimestampProductionTime(List<TimestampWrapper> timestamps, TimestampType... selectedTimestampTypes) {
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

	private boolean isInSelectedTypes(TimestampType[] allowedTypes, TimestampType type) {
		for (TimestampType timestampType : allowedTypes) {
			if (timestampType.equals(type)) {
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
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.TIMESTAMP_ORDER_FAILURE;
	}

}
