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
