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

public class PdfBoxArrayTest {

    @Test
    public void getLongValueTest() throws IOException {
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
    public void getFloatValueTest() throws IOException {
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
