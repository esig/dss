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
package eu.europa.esig.dss.alert.status;

import java.util.Collection;

/**
 * Contains message describing the occurred event
 *
 */
public class MessageStatus implements Status {

    /** Message describing the occurred event */
    private String message;

    /**
     * Default constructor initializing a null message
     */
    public MessageStatus() {
        // empty
    }

    @Override
    public String getMessage() {
        return message;
    }

    /**
     * Sets the message describing the occurred event
     *
     * @param message {@link String}
     */
    public void setMessage(String message) {
        this.message = message;
    }

    @Override
    public Collection<String> getRelatedObjectIds() {
        throw new UnsupportedOperationException("getRelatedObjectIds() is not supported for the current implementation!");
    }

    @Override
    public boolean isEmpty() {
        return message == null || message.length() == 0;
    }

    @Override
    public String getErrorString() {
        return getMessage();
    }

    @Override
    public String toString() {
        return isEmpty() ? "Status : Valid" : getErrorString();
    }

}
