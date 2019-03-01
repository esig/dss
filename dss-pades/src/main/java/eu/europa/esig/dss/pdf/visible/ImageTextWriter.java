/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pdf.visible;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.pades.SignatureImageTextParameters;

/**
 * This class allows to generate image with text
 *
 */
public final class ImageTextWriter {

	private static final Logger LOG = LoggerFactory.getLogger(ImageTextWriter.class);

	private ImageTextWriter() {
	}

	public static BufferedImage createTextImage(final String text, final Font font, final float size, final Color textColor, final Color bgColor,
			final float margin, final int dpi, SignatureImageTextParameters.SignerTextHorizontalAlignment horizontalAlignment) {
		// Computing image size depending on the font
		Font properFont = computeProperFont(font, size, dpi);
		Dimension dimension = computeSize(properFont, text, margin);
		return createTextImage(text, properFont, textColor, bgColor, margin, dimension, horizontalAlignment);
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

	private static BufferedImage createTextImage(final String text, final Font font, final Color textColor, final Color bgColor, final float margin, 
			final Dimension dimension, SignatureImageTextParameters.SignerTextHorizontalAlignment horizontalAlignment) {
		String[] lines = text.split("\n");

		int imageType;
		if (isTransparent(textColor, bgColor)) {
			LOG.warn("Transparency detected and enabled (be careful not valid with PDF/A !)");
			imageType = BufferedImage.TYPE_INT_ARGB;
		} else {
			imageType = BufferedImage.TYPE_INT_RGB;
		}

		BufferedImage img = new BufferedImage(dimension.width, dimension.height, imageType);
		Graphics2D g = img.createGraphics();
		g.setFont(font);
		FontMetrics fm = g.getFontMetrics(font);

		// Improve text rendering
		CommonDrawerUtils.initRendering(g);

		if (bgColor == null) {
			g.setColor(Color.WHITE);
		} else {
			g.setColor(bgColor);
		}
		g.fillRect(0, 0, dimension.width, dimension.height);

		if (textColor == null) {
			g.setPaint(Color.BLACK);
		} else {
			g.setPaint(textColor);
		}

		int lineHeight = fm.getHeight();
		float y = fm.getMaxAscent() + margin;

		for (String line : lines) {
			float x = margin; // left alignment
			if (horizontalAlignment != null) {
				switch (horizontalAlignment) {
					case RIGHT:
						x = img.getWidth() - fm.stringWidth(line) - x; // -x because of margin
						break;
					case CENTER:
						x = (img.getWidth() - fm.stringWidth(line)) / 2;
						break;
					case LEFT:
					default:
						// nothing
						break;
				}
			}
			g.drawString(line, x, y);
			y += lineHeight;
		}
		g.dispose();

		return img;
	}

	private static boolean isTransparent(Color... colors) {
		if (colors != null) {
			for (Color color : colors) {
				int alpha = color.getAlpha();
				if (alpha < 255) {
					return true;
				}
			}
		}
		return false;
	}

}
