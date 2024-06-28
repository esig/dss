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
package eu.europa.esig.dss.pdf;

/**
 * Represents a wrapper for a simple value (Integer, String, etc.), extracted from a PDF
 *
 */
public class PdfSimpleObject implements PdfObject {

    /** Value of the object */
    private final Object value;

    /** Parent of the object */
    private final PdfObject parent;

    /**
     * Default constructor
     *
     * @param value {@link Object}
     */
    public PdfSimpleObject(final Object value) {
        this(value, null);
    }

    /**
     * Constructor with a parent
     *
     * @param value {@link Object} embedded value of the current PDF object
     * @param parent {@link PdfObject}
     */
    public PdfSimpleObject(final Object value, final PdfObject parent) {
        this.value = value;
        this.parent = parent;
    }

    @Override
    public Object getValue() {
        return value;
    }

    @Override
    public PdfObject getParent() {
        return parent;
    }

}
