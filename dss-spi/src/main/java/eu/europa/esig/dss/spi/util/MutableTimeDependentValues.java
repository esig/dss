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
package eu.europa.esig.dss.spi.util;

import java.util.Date;
import java.util.List;

/**
 * Mutable list of time-dependent values.
 * 
 * @author jdvorak
 * @param <T>
 *            sub type of TimeDependent
 */
public class MutableTimeDependentValues<T extends TimeDependent> extends TimeDependentValues<T> {

	public MutableTimeDependentValues() {
		super();
	}

	public MutableTimeDependentValues(final Iterable<T> srcList) {
		super(srcList);
	}

	public synchronized void clear() {
		list.clear();
	}

	public synchronized void addOldest(final T x) {
		if (x == null) {
			throw new NullPointerException("Cannot add null");
		}
		if (!list.isEmpty()) {
			final Date endDate = x.getEndDate();
			for (final T y : list) {
				if (endDate.compareTo(y.getStartDate()) > 0) {
					throw new IllegalArgumentException("Cannot add overlapping item");
				}
			}
		}
		list.add(x);
	}

	public List<T> getList() {
		return list;
	}

}
