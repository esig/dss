/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Checks if the timestamp's order is coherent
 */
public class TimestampCoherenceOrderCheck extends ChainItem<XmlValidationProcessLongTermData> {

	/** List of timestamps to check */
	private final List<TimestampWrapper> timestamps;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlValidationProcessLongTermData}
	 * @param timestamps a list of {@link TimestampWrapper}s
	 * @param constraint {@link LevelRule}
	 */
	public TimestampCoherenceOrderCheck(I18nProvider i18nProvider, XmlValidationProcessLongTermData result,
										List<TimestampWrapper> timestamps, LevelRule constraint) {
		super(i18nProvider, result, constraint);
		this.timestamps = timestamps;
	}

	@Override
	protected boolean process() {
		return Utils.collectionSize(timestamps) <= 1 || checkTimestampCoherenceOrderByType();
	}
	
	private boolean checkTimestampCoherenceOrderByType() {
		List<TimestampWrapper> toBeCheckedTimestamps = new ArrayList<>(timestamps);
		Iterator<TimestampWrapper> tstIterator = toBeCheckedTimestamps.iterator();
		while (tstIterator.hasNext()) {
			TimestampWrapper timestamp = tstIterator.next();
			tstIterator.remove(); // in order do not re-validate the same pairs
			if (!isValidAgainstList(timestamp, toBeCheckedTimestamps)) {
				return false;
			}
		}
		return true;
	}
	
	private boolean isValidAgainstList(TimestampWrapper timestamp, List<TimestampWrapper> timestampList) {
		for (TimestampWrapper timestampToCompare : timestampList) {
			int typeResult = timestamp.getType().compare(timestampToCompare.getType());
			int productionTimeResult = timestamp.getProductionTime().compareTo(timestampToCompare.getProductionTime());
			
			// if time is different and types are in a wrong order
			if (productionTimeResult != 0 && typeResult != productionTimeResult) {
				// if the type is the same, but time is different, check the references
				if (typeResult == 0) {
					// if the first timestamp is created earlier and it covers the next timestamp
					if (productionTimeResult < 0 && coversTheTimestamp(timestamp, timestampToCompare)) {
						return false;
					}
					// if the first timestamp is created after and its covered by the previous timestamp
					else if (productionTimeResult > 0 && coversTheTimestamp(timestampToCompare, timestamp)) {
						return false;
					}
					
				} else {
					return false;
				}
			}
		}
		return true;
	}
	
	private boolean coversTheTimestamp(TimestampWrapper timestamp, TimestampWrapper timestampToCompare) {
		return timestamp.getTimestampedTimestamps().contains(timestampToCompare);
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
