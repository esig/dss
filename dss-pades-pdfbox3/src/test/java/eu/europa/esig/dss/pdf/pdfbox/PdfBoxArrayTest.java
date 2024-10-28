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
package eu.europa.esig.dss.pdf.pdfbox;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSFloat;
import org.apache.pdfbox.cos.COSInteger;
import org.apache.pdfbox.cos.COSNumber;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PdfBoxArrayTest {

    @Test
    void getLongValueTest() throws IOException {
        COSArray cosArray = new COSArray();
        cosArray.add(COSInteger.get(123456789));

        COSBase integer = cosArray.get(0);
        assertNotNull(integer);
        assertTrue(integer instanceof COSNumber);

        try (PDDocument pdDocument = new PDDocument()) {
            PdfBoxArray pdfBoxDict = new PdfBoxArray(cosArray, pdDocument);
            Number numberValue = pdfBoxDict.getNumber(0);
            assertNotNull(numberValue);
            assertEquals(123456789, numberValue.longValue());
        }
    }

    @Test
    void getFloatValueTest() throws IOException {
        COSArray cosArray = new COSArray();
        cosArray.add(COSFloat.get("1.23456789e8"));

        COSBase floatNumber = cosArray.get(0);
        assertNotNull(floatNumber);
        assertTrue(floatNumber instanceof COSFloat);

        try (PDDocument pdDocument = new PDDocument()) {
            PdfBoxArray pdfBoxDict = new PdfBoxArray(cosArray, pdDocument);
            Number numberValue = pdfBoxDict.getNumber(0);
            assertNotNull(numberValue);
            assertEquals(123456789f, numberValue.floatValue());
        }
    }

}
