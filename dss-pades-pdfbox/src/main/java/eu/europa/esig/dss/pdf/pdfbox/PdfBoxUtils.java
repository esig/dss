package eu.europa.esig.dss.pdf.pdfbox;

import java.util.Objects;

import org.apache.pdfbox.pdmodel.PDDocument;

import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfDssDict;

public final class PdfBoxUtils {
	
	private PdfBoxUtils() {
	}

	public static PdfDssDict getDSSDictionary(PDDocument doc) {
		Objects.requireNonNull(doc, "PDDocument cannot be null!");
		PdfDict catalog = new PdfBoxDict(doc.getDocumentCatalog().getCOSObject(), doc);
		return PdfDssDict.extract(catalog);
	}
}
