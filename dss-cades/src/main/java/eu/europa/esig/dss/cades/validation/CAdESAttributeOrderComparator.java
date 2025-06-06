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
