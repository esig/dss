package eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer;

import java.awt.Font;

import org.apache.pdfbox.pdmodel.font.PDType1Font;

import eu.europa.esig.dss.model.DSSException;

public class PdfBoxFontMapper {
	
	public static PDType1Font getPDFont(Font javaFont) {
		switch (javaFont.getFamily()) {
			case Font.SERIF:
				if (javaFont.isPlain()) {
					return PDType1Font.TIMES_ROMAN;
				} else if (javaFont.isBold()) {
					if (javaFont.isItalic()) {
						return PDType1Font.TIMES_BOLD_ITALIC;
					} else {
						return PDType1Font.TIMES_BOLD;
					}
				} else {
					return PDType1Font.TIMES_ITALIC;
				}
			case Font.SANS_SERIF:
				if (javaFont.isPlain()) {
					return PDType1Font.HELVETICA;
				} else if (javaFont.isBold()) {
					if (javaFont.isItalic()) {
						return PDType1Font.HELVETICA_BOLD_OBLIQUE;
					} else {
						return PDType1Font.HELVETICA_BOLD;
					}
				} else {
					return PDType1Font.HELVETICA_OBLIQUE;
				}
			case Font.MONOSPACED:
				if (javaFont.isPlain()) {
					return PDType1Font.COURIER;
				} else if (javaFont.isBold()) {
					if (javaFont.isItalic()) {
						return PDType1Font.COURIER_BOLD_OBLIQUE;
					} else {
						return PDType1Font.COURIER_BOLD;
					}
				} else {
					return PDType1Font.COURIER_OBLIQUE;
				}
			case Font.DIALOG:
			case Font.DIALOG_INPUT:
				return PDType1Font.SYMBOL;
			default:
				throw new DSSException("The font is not supported! Please use DSSFileFont implementation for custom fonts.");
			}
	}

}
