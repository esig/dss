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
package eu.europa.esig.dss.validation.timestamp;

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.validation.ManifestFile;

import java.io.Serializable;
import java.util.Comparator;
import java.util.List;

/**
 * Compares {@code TimestampToken}s
 *
 */
public class TimestampTokenComparator implements Comparator<TimestampToken>, Serializable {

	private static final long serialVersionUID = 3404578959761631884L;

	@Override
	public int compare(TimestampToken tst1, TimestampToken tst2) {
		int result = compareByGenerationTime(tst1, tst2);
		if (result == 0) {
			result = compareByTokenType(tst1, tst2);
		}
		if (result == 0) {
			result = compareByManifest(tst1, tst2);
		}
		if (result == 0) {
			result = compareByCoverage(tst1, tst2);
		}
		if (result == 0) {
			result = compareByTimestampedReferences(tst1, tst2);
		}
		return result;
	}

	private int compareByGenerationTime(TimestampToken tst1, TimestampToken tst2) {
		return tst1.getGenerationTime().compareTo(tst2.getGenerationTime());
	}

	private int compareByTokenType(TimestampToken tst1, TimestampToken tst2) {
		TimestampType tst1Type = tst1.getTimeStampType();
		TimestampType tst2Type = tst2.getTimeStampType();
		return tst1Type.compare(tst2Type);
	}

	private int compareByManifest(TimestampToken tst1, TimestampToken tst2) {
		ManifestFile tst1ManifestFile = tst1.getManifestFile();
		ManifestFile tst2ManifestFile = tst2.getManifestFile();
		if (tst1ManifestFile != null && tst1ManifestFile.isDocumentCovered(tst2.getFileName())) {
			return  1;
		} else if (tst2ManifestFile != null && tst2ManifestFile.isDocumentCovered(tst1.getFileName())) {
			return -1;
		}
		return 0;
	}

	private int compareByCoverage(TimestampToken tst1, TimestampToken tst2) {
		if (isCoveredByTimestamp(tst1, tst2)) {
			return -1;
		} else if (isCoveredByTimestamp(tst2, tst1)) {
			return 1;
		}
		return 0;
	}
	
	private boolean isCoveredByTimestamp(TimestampToken tst1, TimestampToken tst2) {
		List<TimestampedReference> tst2References = tst2.getTimestampedReferences();
		for (TimestampedReference timestampedReference : tst2References) {
			if (tst1.getDSSIdAsString().equals(timestampedReference.getObjectId())) {
				return true;
			}
		}
		return false;
	}

	private int compareByTimestampedReferences(TimestampToken tst1, TimestampToken tst2) {
		List<TimestampedReference> tst1References = tst1.getTimestampedReferences();
		List<TimestampedReference> tst2References = tst2.getTimestampedReferences();
		if (tst1References != null && tst2References != null) {
			if (tst1References.size() < tst2References.size()) {
				return -1;
			} else if (tst1References.size() > tst2References.size()) {
				return 1;
			}
		}
		return 0;
	}

}
