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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlQcEuLimitValue;

/**
 * The class provides a user-friendly API for dealing with {@code XmlQCEuLimitValue}
 *
 */
public class QCLimitValueWrapper {

    /** Wrapped object */
    private final XmlQcEuLimitValue wrapped;

    /**
     * Default constructor
     *
     * @param qcEuLimitValue {@link XmlQcEuLimitValue}
     */
    public QCLimitValueWrapper(XmlQcEuLimitValue qcEuLimitValue) {
        this.wrapped = qcEuLimitValue;
    }

    /**
     * Returns the Iso4217CurrencyCode
     *
     * @return {@link String}
     */
    public String getCurrency() {
        return wrapped.getCurrency();
    }

    /**
     * Returns the defined amount
     *
     * @return int amount
     */
    public int getAmount() {
        return wrapped.getAmount();
    }

    /**
     * Returns the defined exponent
     *
     * @return int exponent
     */
    public int getExponent() {
        return wrapped.getExponent();
    }

}
