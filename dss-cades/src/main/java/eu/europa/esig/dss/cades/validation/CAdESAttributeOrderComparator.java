package eu.europa.esig.dss.cades.validation;

import java.io.Serializable;
import java.util.Comparator;

/**
 * The class is used to compare order and only original order of {@code CAdESAttribute}s from an AttributeTable
 * Class checks the production time of timestamps and their covered data
 * <p>
 * The method compare() returns
 *     -1 if the {@code attributeOne} has original order before {@code attributeTwo}
 *     0 if attributes have the same order (should not happen)
 *     1 if the {@code attributeOne} has original order after {@code attributeTwo}
 *
 */
public class CAdESAttributeOrderComparator implements Comparator<CAdESAttribute>, Serializable {

    private static final long serialVersionUID = -6532983590271180178L;

    /**
     * Default constructor
     */
    public CAdESAttributeOrderComparator() {
        // empty
    }

    @Override
    public int compare(CAdESAttribute attributeOne, CAdESAttribute attributeTwo) {
        if (attributeOne.getOrder() != null && attributeTwo.getOrder() != null) {
            if (attributeOne.getOrder() < attributeTwo.getOrder()) {
                return -1;
            } else if (attributeOne.getOrder() > attributeTwo.getOrder()) {
                return 1;
            }
        }
        return 0;
    }

}
