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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * Immutable list of time-dependent values, with the latest value first.
 * 
 * @author jdvorak
 * @param <T>
 *            sub type of TimeDependent
 */
public class TimeDependentValues<T extends TimeDependent> implements Iterable<T> {

	/** The linked list of values */
	protected final List<T> list = new LinkedList<>();

	/** The immutable list */
	private final List<T> immutableList = Collections.unmodifiableList(list);

	/**
	 * Empty list of values.
	 */
	public TimeDependentValues() {
		super();
	}

	/**
	 * Copy constructor.
	 * 
	 * @param srcList
	 *            an iterable of TimeDependent
	 */
	public TimeDependentValues(final Iterable<T> srcList) {
		for (final T x : srcList) {
			list.add(x);
		}
	}

	@Override
	public Iterator<T> iterator() {
		return immutableList.iterator();
	}

	/**
	 * Gets the latest time dependent value
	 *
	 * @return the latest time dependent value
	 */
	public T getLatest() {
		return (list.isEmpty()) ? null : list.get(0);
	}

	/**
	 * Gets the value with the date {@code d} if present
	 *
	 * @param d {@link Date}
	 * @return the value with the date {@code d} if present, null otherwise
	 */
	public T getCurrent(final Date d) {
		for (final T x : list) {
			if (x.getStartDate().compareTo(d) <= 0) {
				final Date endDate = x.getEndDate();
				if (endDate == null || endDate.compareTo(d) > 0) {
					return x;
				}
			}
		}
		return null;
	}

	/**
	 * Gets a list of time dependent values occurred after {@code notBefore}
	 *
	 * @param notBefore {@link Date}
	 * @return a list of time dependent values
	 */
	public List<T> getAfter(Date notBefore) {
		List<T> result = new ArrayList<>();
		for (final T x : list) {
			Date endDate = x.getEndDate();
			if (endDate == null || (endDate.compareTo(notBefore) >= 0)) {
				result.add(x);
			}
		}
		return result;
	}

	@Override
	public String toString() {
		return list.toString();
	}

}
