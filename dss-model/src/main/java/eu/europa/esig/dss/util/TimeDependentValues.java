package eu.europa.esig.dss.util;

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
 */
public class TimeDependentValues<T extends TimeDependent> implements Iterable<T> {

	protected final List<T> list = new LinkedList<T>();
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

	public T getLatest() {
		return (list.isEmpty()) ? null : list.get(0);
	}

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

	public boolean isEmpty() {
		return list.isEmpty();
	}

}
