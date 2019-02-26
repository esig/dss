package eu.europa.esig.dss.pdf.pdfbox.visible.textSig;

import java.awt.Font;

import org.apache.pdfbox.pdmodel.font.PDType1Font;

public class PdfBoxFontsMapper {
	
	public static PDType1Font getPDFont(Font font) {
		switch (font.getFamily()) {
			case "Dialog":
			case "DialogInput":
				return PDType1Font.SYMBOL;
			case "SansSerif":
				if (font.isBold()) {
					if (font.isItalic()) {
						return PDType1Font.HELVETICA_BOLD_OBLIQUE;
					}
					return PDType1Font.HELVETICA_BOLD;
				} else if (font.isItalic()) {
					return PDType1Font.HELVETICA_OBLIQUE;
				} else {
					return PDType1Font.HELVETICA;
				}
			case "Serif":
				if (font.isBold()) {
					if (font.isItalic()) {
						return PDType1Font.TIMES_BOLD_ITALIC;
					}
					return PDType1Font.TIMES_BOLD;
				} else if (font.isItalic()) {
					return PDType1Font.TIMES_ITALIC;
				} else {
					return PDType1Font.TIMES_ROMAN;
				}
			case "Monospaced":
				if (font.isBold()) {
					if (font.isItalic()) {
						return PDType1Font.COURIER_BOLD_OBLIQUE;
					}
					return PDType1Font.COURIER_BOLD;
				} else if (font.isItalic()) {
					return PDType1Font.COURIER_OBLIQUE;
				} else {
					return PDType1Font.COURIER;
				}
			default:
				// TODO: custom fonts need to be implemented
				return null;
		}
	}

}
