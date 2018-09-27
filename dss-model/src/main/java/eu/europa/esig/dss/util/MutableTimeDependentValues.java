package eu.europa.esig.dss.util;

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
