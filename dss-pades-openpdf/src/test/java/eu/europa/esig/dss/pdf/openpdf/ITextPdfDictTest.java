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

import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfNumber;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class ITextPdfDictTest {

    @Test
    public void getLongValueTest() {
        PdfDictionary pdfDictionary = new PdfDictionary();
        pdfDictionary.put(new PdfName("Integer"), new PdfNumber(123456789));

        PdfNumber integer = pdfDictionary.getAsNumber(new PdfName("Integer"));
        assertNotNull(integer);

        ITextPdfDict pdfBoxDict = new ITextPdfDict(pdfDictionary);
        Number numberValue = pdfBoxDict.getNumberValue("Integer");
        assertNotNull(numberValue);
        assertEquals(123456789, numberValue.longValue());
    }

    @Test
    public void getFloatValueTest() {
        PdfDictionary pdfDictionary = new PdfDictionary();
        pdfDictionary.put(new PdfName("Float"), new PdfNumber("1.23456789e8"));

        PdfNumber floatNumber = pdfDictionary.getAsNumber(new PdfName("Float"));
        assertNotNull(floatNumber);

        ITextPdfDict pdfBoxDict = new ITextPdfDict(pdfDictionary);
        Number numberValue = pdfBoxDict.getNumberValue("Float");
        assertNotNull(numberValue);
        assertEquals(123456789f, numberValue.floatValue());
    }

}
