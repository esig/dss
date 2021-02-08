/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.model.x509;

/**
 * Defines limits of transactions for a given certificate (QcStatement)
 */
public class QCLimitValue {

    /** The used currency */
    private String currency;

    /** The transaction amount */
    private int amount;

    /** The exponent */
    private int exponent;

    /**
     * Gets the currency
     *
     * @return {@link String}
     */
    public String getCurrency() {
        return currency;
    }

    /**
     * Sets the currency
     *
     * @param currency {@link String}
     */
    public void setCurrency(String currency) {
        this.currency = currency;
    }

    /**
     * Gets the amount
     *
     * @return integer
     */
    public int getAmount() {
        return amount;
    }

    /**
     * Sets the amount
     *
     * @param amount integer
     */
    public void setAmount(int amount) {
        this.amount = amount;
    }

    /**
     * Gets the exponent
     *
     * @return integer
     */
    public int getExponent() {
        return exponent;
    }

    /**
     * Sets the exponent
     *
     * @param exponent integer
     */
    public void setExponent(int exponent) {
        this.exponent = exponent;
    }

}
