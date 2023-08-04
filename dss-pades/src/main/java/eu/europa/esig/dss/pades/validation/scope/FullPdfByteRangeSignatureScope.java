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
package eu.europa.esig.dss.pades.validation.scope;

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.validation.ByteRange;

/**
 * Represents a FULL Pdf signature scope (signature/timestamp covers a complete PDF file)
 *
 */
public class FullPdfByteRangeSignatureScope extends PdfByteRangeSignatureScope {

    private static final long serialVersionUID = -1284820739809488661L;

    /** A string used for a fully covered PDF representation */
    private static final String FULL_PDF = "Full PDF";

    /**
     * Default constructor
     *
     * @param byteRange {@link ByteRange} used byte range
     * @param document {@link DSSDocument} pdf revision document
     */
    public FullPdfByteRangeSignatureScope(final ByteRange byteRange, final DSSDocument document) {
        super(FULL_PDF, byteRange, document);
    }

    @Override
    public SignatureScopeType getType() {
        return SignatureScopeType.FULL;
    }

}
