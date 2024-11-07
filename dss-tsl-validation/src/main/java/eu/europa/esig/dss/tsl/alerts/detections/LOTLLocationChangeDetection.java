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
package eu.europa.esig.dss.tsl.alerts.detections;

import eu.europa.esig.dss.alert.detector.AlertDetector;
import eu.europa.esig.dss.model.tsl.LOTLInfo;
import eu.europa.esig.dss.model.tsl.PivotInfo;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

/**
 * Detects the change of a LOTL location
 */
public class LOTLLocationChangeDetection implements AlertDetector<LOTLInfo> {

	/** The LOTL source */
	private final LOTLSource lotlSource;

	/**
	 * Default constructor
	 *
	 * @param lotlSource {@link LOTLSource}
	 */
	public LOTLLocationChangeDetection(LOTLSource lotlSource) {
		this.lotlSource = lotlSource;
	}

	@Override
	public boolean detect(LOTLInfo info) {

		if (Utils.areStringsEqual(lotlSource.getUrl(), info.getUrl()) && lotlSource.isPivotSupport()) {

			List<PivotInfo> pivotInfos = info.getPivotInfos();
			if (Utils.isCollectionNotEmpty(pivotInfos)) {
				PivotInfo lastPivotInfo = pivotInfos.get(pivotInfos.size() - 1);
				if (!Utils.areStringsEqual(lastPivotInfo.getLOTLLocation(), info.getUrl())) {
					return true;
				}
			}
		}
		return false;
	}

}
