package eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer;

import java.io.IOException;

import org.apache.pdfbox.pdmodel.font.PDFont;

import eu.europa.esig.dss.pdf.visible.CommonDrawerUtils;

public class NativePdfBoxDrawerUtils {
	
	/**
	 * Computes width for a single string
	 * 
	 * @param pdFont {@link PDFont} of the text
	 * @param fontSize float size of the font
	 * @param str {@link String} text
	 * @param dpi integer dpi
	 * @return string width
	 * @throws IOException if an exception occurs
	 */
	public static float getTextWidth(PDFont pdFont, float fontSize, String str) throws IOException {
		return pdFont.getStringWidth(str) / 1000 * fontSize;
	}
	
	/**
	 * Computes height for a single string
	 * 
	 * @param pdFont {@link PDFont} of the text
	 * @param fontSize float size of the font
	 * @param dpi integer dpi
	 * @return string height
	 * @throws IOException if an exception occurs
	 */
	public static float getTextHeight(PDFont pdFont, float fontSize) throws IOException {
		return pdFont.getBoundingBox().getHeight() / 1000 * fontSize;
	}

}
