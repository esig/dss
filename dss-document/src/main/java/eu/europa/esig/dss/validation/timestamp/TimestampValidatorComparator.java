package eu.europa.esig.dss.validation.timestamp;

import java.io.Serializable;
import java.util.Comparator;

/**
 * Compares {@code TimestampValidator}s
 *
 */
public class TimestampValidatorComparator implements Comparator<TimestampValidator>, Serializable {

    /** Used to compare the timestamps */
    private static final TimestampTokenComparator timestampComparator = new TimestampTokenComparator();

    @Override
    public int compare(TimestampValidator tstValidator1, TimestampValidator tstValidator2) {
        return timestampComparator.compare(tstValidator1.getTimestamp(), tstValidator2.getTimestamp());
    }

}
