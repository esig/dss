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
package eu.europa.esig.dss.model.x509.extension;

import eu.europa.esig.dss.enumerations.GeneralNameType;

import java.io.Serializable;

/**
 * Represents a general name element (see RFC 5280)
 *
 */
public class GeneralName implements Serializable {

    /** Represents the type of the GeneralName */
    private GeneralNameType generalNameType;

    /** String representation of the GeneralName value */
    private String value;

    /**
     * Default constructor
     */
    public GeneralName() {
        // empty
    }

    /**
     * Gets the type of GeneralName
     *
     * @return {@link GeneralNameType}
     */
    public GeneralNameType getGeneralNameType() {
        return generalNameType;
    }

    /**
     * Sets the type of the GeneralName
     *
     * @param generalNameType {@link GeneralNameType}
     */
    public void setGeneralNameType(GeneralNameType generalNameType) {
        this.generalNameType = generalNameType;
    }

    /**
     * Gets the string representation of the GeneralName value
     *
     * @return {@link String}
     */
    public String getValue() {
        return value;
    }

    /**
     * Sets the string representation of the GeneralName value
     *
     * @param value {@link String}
     */
    public void setValue(String value) {
        this.value = value;
    }

}
