package eu.europa.esig.dss.validation;

import java.io.Serializable;
import java.util.Comparator;

public class TimestampByGenerationTimeComparator implements Comparator<TimestampToken>, Serializable {

	private static final long serialVersionUID = -9130280943645913494L;

	@Override
	public int compare(TimestampToken t1, TimestampToken t2) {
		return t1.getGenerationTime().compareTo(t2.getGenerationTime());
	}

}
