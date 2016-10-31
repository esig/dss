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
package eu.europa.esig.dss.pades.signature.visible;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;

import eu.europa.esig.dss.pades.TextAlignment;

/**
 * This class allows to generate image with text
 *
 */
public final class ImageTextWriter {

	private static final int DEFAULT_MARGIN = 10;

	private ImageTextWriter() {
	}

	public static BufferedImage createTextImage(final String text, final Font font, final Color textColor, final Color bgColor, final int dpi, final TextAlignment horizontalTextAlignment) {
		// Computing image size depending of the font
		float fontSize = Math.round((font.getSize() * dpi) / 72.0);
		Font largerFont = font.deriveFont(fontSize);
		Dimension dimension = computeSize(largerFont, text);
		// gettters returns doubles ??
		return createTextImage(text, largerFont, textColor, bgColor, dimension.width, dimension.height, horizontalTextAlignment);
	}

	public static Dimension computeSize(Font font, String text) {
		BufferedImage img = new BufferedImage(1, 1, BufferedImage.TYPE_INT_RGB);
		Graphics g = img.getGraphics();
		g.setFont(font);
		FontMetrics fontMetrics = g.getFontMetrics();

		int width = getMultilineTextWidth(text, fontMetrics) + DEFAULT_MARGIN;
		int height = getMultilineTextHeight(text, fontMetrics) + DEFAULT_MARGIN;
		return new Dimension(width, height);
	}

	/**
	 * Calculates multi-line text width as the widest line width plus the default margin.
	 *
	 * @param text             multi-line text (\n denotes a line break)
	 * @param fontMetrics       font metrics
	 *
	 * @return width of the widest multi-line text line
	 */
	private static int getMultilineTextWidth(final String text, final FontMetrics fontMetrics) {
		int maxLineWidth = 0;
		for (String line : text.split("\n")) {
			int lineWidth = fontMetrics.stringWidth(line);
			if (lineWidth > maxLineWidth) maxLineWidth = lineWidth;
		}
		return maxLineWidth;
	}

	/**
	 * Calculates multi-line text height as the sum of all line heights plus the default margin.
	 *
	 * @param fontMetrics
	 * @return
	 */
	private static int getMultilineTextHeight(final String text, final FontMetrics fontMetrics) {
		int textHeight = 0;
		for (String ignored : text.split("\n")) textHeight += fontMetrics.getHeight();
		return textHeight;
	}

	private static BufferedImage createTextImage(final String text, final Font font, final Color textColor, final Color bgColor, final int width,
	                                             final int height, final TextAlignment horizontalTextAlignment) {
		BufferedImage img = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);

		Graphics2D g = img.createGraphics();

		// Improve text rendering
		g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
		g.setRenderingHint(RenderingHints.KEY_COLOR_RENDERING, RenderingHints.VALUE_COLOR_RENDER_QUALITY);
		g.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
		g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

		g.setColor(bgColor);
		g.fillRect(0, 0, width, height);

		g.setPaint(textColor);
		g.setFont(font);
		FontMetrics fm = g.getFontMetrics();

		int x = img.getWidth() - getMultilineTextWidth(text, fm);
		int y = ((img.getHeight() - getMultilineTextHeight(text, fm)) / 2) + fm.getAscent();

		drawMultilineString(text, g, fm, x, y, img.getWidth(), horizontalTextAlignment);
		g.dispose();

		return img;
	}

	/**
	 * Draws multi-line string at the specified coordinates.
	 * @param text                  multi-line string
	 * @param g                     2D renderer
	 * @param fontMetrics           text font metrics
	 * @param x                     x position of the first line of text
	 * @param y                     y position of the baseline of the first line of text
	 * @param boxWidth              text box width
	 * @param horizontalAlignment   horizontal text alignment
	 */
	private static void drawMultilineString(final String text, final Graphics2D g, final FontMetrics fontMetrics, final int x, final int y, final int boxWidth, final TextAlignment horizontalAlignment) {
		// draw the lines
		int lineY = y;
		for (String line : text.split("\n")) {
			// determine text line x position for the specified text horizontal alignment
			int lineX = x - (DEFAULT_MARGIN / 2);
			if (horizontalAlignment == TextAlignment.HORIZONTAL_CENTER) lineX += (boxWidth - fontMetrics.stringWidth(line)) / 2 - (DEFAULT_MARGIN / 2);
			else if (horizontalAlignment == TextAlignment.HORIZONTAL_RIGHT) lineX += (boxWidth - fontMetrics.stringWidth(line)) - DEFAULT_MARGIN;

			// draw the line
			g.drawString(line, lineX, lineY);

			// move to the next line
			lineY += fontMetrics.getHeight();
		}
	}
}
