package eu.europa.esig.dss.pdf.pdfbox.visible.defaultdrawer;

import java.awt.FontMetrics;

import eu.europa.esig.dss.pdf.visible.AbstractFontMetrics;

public class JavaFontMetrics extends AbstractFontMetrics {
	
	private final FontMetrics fontMetrics;
	
	public JavaFontMetrics(FontMetrics fontMetrics) {
		this.fontMetrics = fontMetrics;
	}

	@Override
	public float getWidth(String str, float size) {
		return fontMetrics.stringWidth(str);
	}

	@Override
	public float getHeight(String str, float size) {
		return fontMetrics.getHeight();
	}

}
