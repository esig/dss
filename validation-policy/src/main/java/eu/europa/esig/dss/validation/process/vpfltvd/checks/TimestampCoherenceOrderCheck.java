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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.vpfltvd.TimestampByGenerationTimeComparator;

public class TimestampCoherenceOrderCheck extends ChainItem<XmlValidationProcessLongTermData> {

	private static final Logger LOG = LoggerFactory.getLogger(TimestampCoherenceOrderCheck.class);

	private final List<TimestampWrapper> timestamps;

	public TimestampCoherenceOrderCheck(XmlValidationProcessLongTermData result, List<TimestampWrapper> timestamps, LevelConstraint constraint) {
		super(result, constraint);
		this.timestamps = timestamps;
	}

	@Override
	protected boolean process() {
		if (Utils.collectionSize(timestamps) <= 1 || checkTimestampCoherenceOrderByType() && checkArchiveTimestampCoherenceOrder()) {
			return true;
		}
		return false;
	}
	
	private boolean checkTimestampCoherenceOrderByType() {
		
		Date latestContent = getLatestTimestampProductionDate(timestamps, TimestampType.getContentTimestampTypes());

		Date earliestSignature = getEarliestTimestampProductionTime(timestamps, TimestampType.SIGNATURE_TIMESTAMP);
		Date latestSignature = getLatestTimestampProductionDate(timestamps, TimestampType.SIGNATURE_TIMESTAMP);

		TimestampType[] timestampTypesCoveringValidationData = new TimestampType[] 
				{TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP, TimestampType.VALIDATION_DATA_TIMESTAMP};
		Date earliestValidationData = getEarliestTimestampProductionTime(timestamps, timestampTypesCoveringValidationData);
		Date latestValidationData = getLatestTimestampProductionDate(timestamps, timestampTypesCoveringValidationData);

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
	
	private boolean checkArchiveTimestampCoherenceOrder() {
		List<TimestampWrapper> archiveTimestamps = getOrderedArchiveTimestampsByTime();
		if (Utils.isCollectionEmpty(archiveTimestamps)) {
			return true;
		}
		int timestampedObjectsAmount = 0;
		for (TimestampWrapper timestamp : archiveTimestamps) {
			List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
			if (Utils.isCollectionEmpty(timestampedObjects)) {
				LOG.warn("A timestamp with id [{}] does not have timestamped objects!", timestamp.getId());
				return false;
			}
			// if a newer timestamp covers less or the same value of objects
			if (timestampedObjects.size() <= timestampedObjectsAmount) {
				return false;
			}
			timestampedObjectsAmount = timestampedObjects.size();
		}
		return true;
	}
	
	private List<TimestampWrapper> getOrderedArchiveTimestampsByTime() {
		List<TimestampWrapper> archiveTimestamps = new ArrayList<TimestampWrapper>();
		for (TimestampWrapper timestamp : timestamps) {
			if (timestamp.getType().isArchivalTimestamp()) {
				archiveTimestamps.add(timestamp);
			}
		}
		Collections.sort(archiveTimestamps, new TimestampByGenerationTimeComparator());
		return archiveTimestamps;
	}

	@Override
	protected String getMessageTag() {
		return "TSV_ASTPTCT";
	}

	@Override
	protected String getErrorMessageTag() {
		return "TSV_ASTPTCT_ANS";
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
