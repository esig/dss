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
package eu.europa.esig.dss.enumerations;

/**
 * Represents possible types of a GeneralName
 */
public enum GeneralNameType {

    OTHER_NAME(0, "otherName"),

    RFC822_NAME(1, "rfc822Name"),

    DNS_NAME(2, "dNSName"),

    X400_ADDRESS(3, "x400Address"),

    DIRECTORY_NAME(4, "directoryName"),

    EDI_PARTY_NAME(5, "ediPartyName"),

    UNIFORM_RESOURCE_IDENTIFIER(6, "uniformResourceIdentifier"),

    IP_ADDRESS(7, "iPAddress"),

    REGISTERED_ID(8, "registeredID");

    /** Index of the GeneralName */
    private final int index;

    /** Human-readable label */
    private final String label;

    /**
     * Default constructor
     *
     * @param index int index value
     * @param label {@link String}
     */
    GeneralNameType(final int index, final String label) {
        this.index = index;
        this.label = label;
    }

    /**
     * Gets index of the GeneralName type
     *
     * @return int index
     */
    public int getIndex() {
        return index;
    }

    /**
     * Gets a human-readable label of the GeneralName type
     *
     * @return {@link String}
     */
    public String getLabel() {
        return label;
    }

    /**
     * Returns a {@code GeneralNameType} for the given index if exists
     *
     * @param index int index to get value for
     * @return {@link GeneralNameType} if found, null otherwise
     */
    public static GeneralNameType fromIndex(int index) {
        for (GeneralNameType generalNameType : values()) {
            if (index == generalNameType.index) {
                return generalNameType;
            }
        }
        return null;
    }

    /**
     * Returns a {@code GeneralNameType} for the given label if exists
     *
     * @param label {@link String} representing a human-readable value of the general name type
     * @return {@link GeneralNameType} if found, null otherwise
     */
    public static GeneralNameType fromLabel(String label) {
        for (GeneralNameType generalNameType : values()) {
            if (label.equals(generalNameType.label)) {
                return generalNameType;
            }
        }
        return null;
    }

}
