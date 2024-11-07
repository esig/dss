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
package eu.europa.esig.dss.pdf.openpdf;

import com.lowagie.text.pdf.PdfIndirectReference;
import eu.europa.esig.dss.pades.validation.PdfObjectKey;

import java.util.Objects;

/**
 * OpenPdf (iText) implementation of a PDF object identifier
 *
 */
public class ITextObjectKey implements PdfObjectKey {

    /** Value identifying the PDF object */
    private final PdfIndirectReference value;

    /**
     * Default constructor
     *
     * @param value {@link PdfIndirectReference}
     */
    public ITextObjectKey(final PdfIndirectReference value) {
        this.value = value;
    }

    @Override
    public PdfIndirectReference getValue() {
        return value;
    }

    @Override
    public long getNumber() {
        return value.getNumber();
    }

    @Override
    public int getGeneration() {
        return value.getGeneration();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ITextObjectKey that = (ITextObjectKey) o;
        return Objects.equals(value.toString(), that.value.toString());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(value.toString());
    }

}
