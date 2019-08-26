package eu.europa.esig.dss.pdf.visible;

import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.image.BufferedImage;

import eu.europa.esig.dss.pades.DSSFont;

public class FontUtils {
	
	private FontUtils() {
	}
	
	/**
	 * Computes a new {@link Font} based on the given size and dpi
	 * @param font {@link Font} original font
	 * @param size of the target font
	 * @param dpi used to compute a new font size
	 * @return proper {@link Font}
	 */
	public static Font computeProperFont(Font font, float size, int dpi) {
		float fontSize = CommonDrawerUtils.computeProperSize(size, dpi);
		return font.deriveFont(fontSize);
	}
	
	public static FontMetrics getFontMetrics(Font font) {
		BufferedImage img = new BufferedImage(1, 1, BufferedImage.TYPE_INT_RGB);
		Graphics g = img.getGraphics();
		g.setFont(font);
		FontMetrics fontMetrics = g.getFontMetrics(font);
		g.dispose();
		return fontMetrics;
	}
	
	public static Dimension computeSize(DSSFont dssFont, String text, float margin) {
		return computeSize(dssFont.getJavaFont(), text, margin);
	}
	
	public static Dimension computeSize(Font font, String text, float margin) {
		return computeSize(getFontMetrics(font), text, margin);
	}

	public static Dimension computeSize(FontMetrics fontMetrics, String text, float margin) {
		String[] lines = text.split("\\r?\\n");
		float width = 0;
		for (String line : lines) {
			float lineWidth = fontMetrics.stringWidth(line);
			if (lineWidth > width) {
				width = lineWidth;
			}
		}
		float doubleMargin = margin*2;
		width += doubleMargin;
		float height = (fontMetrics.getHeight() * lines.length) + doubleMargin;
		
		Dimension dimension = new Dimension();
		dimension.setSize(width, height);
		return dimension;
	}

}
