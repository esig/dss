package eu.europa.esig.dss.pdf.openpdf.visible;

import com.lowagie.text.pdf.BaseFont;

import eu.europa.esig.dss.pdf.visible.AbstractFontMetrics;

public class ITextFontMetrics extends AbstractFontMetrics {
	
	private final BaseFont baseFont;
	
	public ITextFontMetrics(BaseFont baseFont) {
		this.baseFont = baseFont;
	}

	@Override
	public float getWidth(String str, float size) {
		return baseFont.getWidthPoint(str, size);
	}

	@Override
	public float getHeight(String str, float size) {
		float ascent = baseFont.getAscentPoint(str, size);
		float descent = baseFont.getDescentPoint(str, size);
		return ascent - descent;
	}

}
