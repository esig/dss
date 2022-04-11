package eu.europa.esig.dss.pdf.openpdf;

import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfNumber;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class ITextPdfArrayTest {

    @Test
    public void getLongValueTest() {
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
    public void getFloatValueTest() {
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
