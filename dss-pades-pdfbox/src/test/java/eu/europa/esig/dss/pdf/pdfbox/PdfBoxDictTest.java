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
package eu.europa.esig.dss.pdf.pdfbox;

import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSFloat;
import org.apache.pdfbox.cos.COSInteger;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSNumber;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PdfBoxDictTest {

    @Test
    void getLongValueTest() throws IOException {
        COSDictionary cosDictionary = new COSDictionary();
        cosDictionary.setItem(COSName.getPDFName("Integer"), COSInteger.get(123456789));

        COSBase integer = cosDictionary.getDictionaryObject(COSName.getPDFName("Integer"));
        assertNotNull(integer);
        assertTrue(integer instanceof COSNumber);

        try (PDDocument pdDocument = new PDDocument()) {
            PdfBoxDict pdfBoxDict = new PdfBoxDict(cosDictionary, pdDocument);
            Number numberValue = pdfBoxDict.getNumberValue("Integer");
            assertNotNull(numberValue);
            assertEquals(123456789, numberValue.longValue());
        }
    }

    @Test
    void getFloatValueTest() throws IOException {
        COSDictionary cosDictionary = new COSDictionary();
        cosDictionary.setItem(COSName.getPDFName("Float"), COSFloat.get("1.23456789e8"));

        COSBase floatNumber = cosDictionary.getDictionaryObject(COSName.getPDFName("Float"));
        assertNotNull(floatNumber);
        assertTrue(floatNumber instanceof COSFloat);

        try (PDDocument pdDocument = new PDDocument()) {
            PdfBoxDict pdfBoxDict = new PdfBoxDict(cosDictionary, pdDocument);
            Number numberValue = pdfBoxDict.getNumberValue("Float");
            assertNotNull(numberValue);
            assertEquals(123456789f, numberValue.floatValue());
        }
    }

}
