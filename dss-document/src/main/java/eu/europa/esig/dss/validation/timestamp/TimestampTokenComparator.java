package eu.europa.esig.dss.validation.timestamp;

import java.io.Serializable;
import java.util.Comparator;
import java.util.List;

import eu.europa.esig.dss.enumerations.TimestampType;

public class TimestampTokenComparator implements Comparator<TimestampToken>, Serializable {

	private static final long serialVersionUID = 3404578959761631884L;

	@Override
	public int compare(TimestampToken tst1, TimestampToken tst2) {
		
		int result = tst1.getGenerationTime().compareTo(tst2.getGenerationTime());
		
		if (result == 0) {
			TimestampType tst1Type = tst1.getTimeStampType();
			TimestampType tst2Type = tst2.getTimeStampType();
			result = tst1Type.compare(tst2Type);
		}

		if (result == 0) {
			List<TimestampedReference> tst1References = tst1.getTimestampedReferences();
			List<TimestampedReference> tst2References = tst2.getTimestampedReferences();
			if (tst1References != null && tst2References != null) {
				if (tst1References.size() < tst2References.size()) {
					result = -1;
				} else if (tst1References.size() > tst2References.size()) {
					result = 1;
				}
			}
		}
		
		return result;
	}

}
