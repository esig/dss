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
package eu.europa.esig.dss.validation.process.vpfswatsp;

import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.TimestampType;

import java.io.Serializable;
import java.util.Comparator;
import java.util.List;

/**
 * The class compares two {@code POE} instances, by its production time, origin and covered context
 * 
 * The class returns the following values:
 * -1 if the poe1 is preferred over poe2
 * 0 of the POEs are equal
 * 1 if the poe2 is preferred over poe1
 *
 */
public class POEComparator implements Comparator<POE>, Serializable {

	private static final long serialVersionUID = -4256501779628944917L;

	/**
	 * Default constructor
	 */
	public POEComparator() {
		// empty
	}

	@Override
	public int compare(POE poe1, POE poe2) {
		int result = compareByTime(poe1, poe2);
		if (result == 0) {
			result = compareByType(poe1, poe2);
		}
		if (result == 0) {
			result = compareByTimestampType(poe1, poe2);
		}
		if (result == 0) {
			result = compareByTimestampedReferences(poe1, poe2);
		}
		return result;
	}

	private int compareByTime(POE poe1, POE poe2) {
		return poe1.getTime().compareTo(poe2.getTime());
	}

	private int compareByType(POE poe1, POE poe2) {
		// POE defined by a timestamp is preferred over a POE defined by a control time
		if (poe1.isTokenProvided() && !poe2.isTokenProvided()) {
			return -1;
		} else if (!poe1.isTokenProvided() && poe2.isTokenProvided()) {
			return 1;
		}
		return 0;
	}

	private int compareByTimestampType(POE poe1, POE poe2) {
		if (poe1 instanceof TimestampPOE && poe2 instanceof TimestampPOE) {
			TimestampType poe1TstType = ((TimestampPOE) poe1).getTimestampType();
			TimestampType poe2TstType = ((TimestampPOE) poe2).getTimestampType();
			if (poe1TstType != null && poe2TstType != null) {
				return poe1TstType.compare(poe2TstType);
			}

		}
		return 0;
	}

	private int compareByTimestampedReferences(POE poe1, POE poe2) {
		List<XmlTimestampedObject> poe1References = poe1.getPOEObjects();
		List<XmlTimestampedObject> poe2References = poe2.getPOEObjects();
		if (poe1References != null && poe2References != null) {
			if (poe1References.size() < poe2References.size()) {
				return -1;
			} else if (poe1References.size() > poe2References.size()) {
				return 1;
			}
		}
		return 0;
	}
	
	/**
	 * Checks if the {@code poe1} is before the {@code poe2}
	 * 
	 * @param poe1 {@link POE} to check if it is before the {@code poe2}
	 * @param poe2 {@link POE} to compare with
	 * @return TRUE if the {@code poe1} is before {@code poe2}, FALSE otherwise
	 */
	public boolean before(POE poe1, POE poe2) {
		return compare(poe1, poe2) < 0;
	}

}
