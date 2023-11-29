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
package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.model.CommonDocument;
import eu.europa.esig.dss.model.DSSDocument;

import java.io.InputStream;
import java.util.Objects;

/**
 * Internal representation of a PDF document. Used to reduce memory overloading during the execution.
 *
 */
public class PdfByteRangeDocument extends CommonDocument {

    private static final long serialVersionUID = 7879399189697068569L;

    /** Input PDF document to read */
    private final DSSDocument pdfDocument;

    /** The ByteRange to be read */
    private final ByteRange byteRange;

    /**
     * Default constructor
     *
     * @param pdfDocument {@link DSSDocument} input PDF document to read
     * @param byteRange {@link ByteRange} of the revision to be read
     */
    public PdfByteRangeDocument(final DSSDocument pdfDocument, final ByteRange byteRange) {
        Objects.requireNonNull(pdfDocument, "PdfDocument cannot be null!");
        Objects.requireNonNull(byteRange, "ByteRange cannot be null!");

        this.pdfDocument = pdfDocument;
        this.byteRange = byteRange;
    }

    /**
     * Returns the {@code ByteRange} of the document
     *
     * @return {@link ByteRange}
     */
    public ByteRange getByteRange() {
        return byteRange;
    }

    @Override
    public InputStream openStream() {
        return new ByteRangeInputStream(pdfDocument.openStream(), byteRange);
    }

}
