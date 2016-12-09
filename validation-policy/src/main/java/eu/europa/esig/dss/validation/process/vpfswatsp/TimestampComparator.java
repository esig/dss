package eu.europa.esig.dss.validation.process.vpfswatsp;

import java.io.Serializable;
import java.util.Comparator;

import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;

public class TimestampComparator implements Comparator<TimestampWrapper>, Serializable {

	private static final long serialVersionUID = -6294844836367054682L;

	@Override
	public int compare(TimestampWrapper t1, TimestampWrapper t2) {
		return t2.getProductionTime().compareTo(t1.getProductionTime());
	}

}
