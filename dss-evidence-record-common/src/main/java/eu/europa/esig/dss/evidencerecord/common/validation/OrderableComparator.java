package eu.europa.esig.dss.evidencerecord.common.validation;

import java.io.Serializable;
import java.util.Comparator;

/**
 * Compares {@code Orderable}
 */
public class OrderableComparator implements Comparator<Orderable>, Serializable {

    private static final long serialVersionUID = -5895541156960486215L;

    /**
     * Default constructor
     */
    public OrderableComparator() {
        // empty
    }

    @Override
    public int compare(Orderable o1, Orderable o2) {
        if (o1.getOrder() < o2.getOrder()) {
            return -1;
        } else if (o1.getOrder() > o2.getOrder()) {
            return 1;
        }
        return 0;
    }

}
