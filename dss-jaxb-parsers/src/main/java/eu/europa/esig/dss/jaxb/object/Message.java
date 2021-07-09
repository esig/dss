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
package eu.europa.esig.dss.jaxb.object;

import java.util.Objects;

/**
 * Represents the Message returned in the validation process
 */
public class Message {

    /** Represents the message key */
    private final String key;

    /** Represents the message text value */
    private final String value;

    /**
     * Default constructor
     *
     * @param key {@link String}
     * @param value {@link String}
     */
    public Message(final String key, final String value) {
        this.key = key;
        this.value = value;
    }

    /**
     * Gets the message key.
     *
     * @return {@link String}
     *
     */
    public String getKey() {
        return key;
    };

    /**
     * Gets the value of the message.
     *
     * @return {@link String}
     */
    public String getValue() {
        return value;
    };

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Message message = (Message) o;

        if (!Objects.equals(key, message.key)) return false;
        return Objects.equals(value, message.value);
    }

    @Override
    public int hashCode() {
        int result = key != null ? key.hashCode() : 0;
        result = 31 * result + (value != null ? value.hashCode() : 0);
        return result;
    }

}
