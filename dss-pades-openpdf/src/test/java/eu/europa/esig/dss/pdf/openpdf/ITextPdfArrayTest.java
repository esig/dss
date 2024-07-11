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
package eu.europa.esig.dss.pdf.openpdf;

import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfNumber;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ITextPdfArrayTest {

    @Test
    void getLongValueTest() {
        PdfArray pdfArray = new PdfArray();
        pdfArray.add(new PdfNumber(123456789));

        PdfNumber integer = pdfArray.getAsNumber(0);
        assertNotNull(integer);

        ITextPdfArray pdfBoxDict = new ITextPdfArray(pdfArray);
        Number numberValue = pdfBoxDict.getNumber(0);
        assertNotNull(numberValue);
        assertEquals(123456789, numberValue.longValue());
    }

    @Test
    void getFloatValueTest() {
        PdfArray pdfArray = new PdfArray();
        pdfArray.add(new PdfNumber("1.23456789e8"));

        PdfNumber floatNumber = pdfArray.getAsNumber(0);
        assertNotNull(floatNumber);

        ITextPdfArray pdfBoxDict = new ITextPdfArray(pdfArray);
        Number numberValue = pdfBoxDict.getNumber(0);
        assertNotNull(numberValue);
        assertEquals(123456789f, numberValue.floatValue());
    }

}
