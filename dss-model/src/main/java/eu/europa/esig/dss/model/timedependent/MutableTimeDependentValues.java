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
package eu.europa.esig.dss.model.timedependent;

import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Mutable list of time-dependent values.
 * 
 * @author jdvorak
 * @param <T>
 *            sub type of TimeDependent
 */
public class MutableTimeDependentValues<T extends TimeDependent> extends TimeDependentValues<T> {

	private static final long serialVersionUID = -7260622365917872977L;

	/**
	 * Empty constructor
	 */
	public MutableTimeDependentValues() {
		super();
	}

	/**
	 * Default constructor
	 *
	 * @param srcList list of time dependent values
	 */
	public MutableTimeDependentValues(final Iterable<T> srcList) {
		super(srcList);
	}

	/**
	 * Clears the current list
	 */
	public synchronized void clear() {
		list.clear();
	}

	/**
	 * Adds the value only of it is the oldest in the current list
	 *
	 * @param x the time dependent value to add
	 */
	public synchronized void addOldest(final T x) {
		Objects.requireNonNull(x, "Cannot add null");
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

	/**
	 * Gets the current list
	 *
	 * @return list of time dependent values
	 */
	public List<T> getList() {
		return list;
	}

}
