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
package eu.europa.esig.dss.pdf.pdfbox.visible.defaultdrawer;

import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.pades.DSSFont;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.visible.CommonDrawerUtils;

/**
 * This class allows to generate image with text
 *
 */
public final class ImageTextWriter {

	private static final Logger LOG = LoggerFactory.getLogger(ImageTextWriter.class);

	private ImageTextWriter() {
	}

	/**
	 * Creates an image representing the specified text
	 * 
	 * @param imageParameters {@link SignatureImageParameters} to use
	 * @return {@link BufferedImage} of the text picture
	 */
	public static BufferedImage createTextImage(final SignatureImageParameters imageParameters) {
		// Computing image size depending on the font
		SignatureImageTextParameters textParameters = imageParameters.getTextParameters();

		DSSFont dssFont = textParameters.getFont();
		float fontSize = CommonDrawerUtils.computeProperSize(dssFont.getSize(), imageParameters.getDpi());

		Font javaFont = dssFont.getJavaFont();
		Font properFont = javaFont.deriveFont(fontSize);

		FontMetrics fontMetrics = getFontMetrics(properFont);
		JavaFontMetrics javaFontMetrics = new JavaFontMetrics(fontMetrics);

		AnnotationBox textBox = javaFontMetrics.computeTextBoundaryBox(textParameters.getText(), fontSize,
				textParameters.getPadding());
		return createTextImage(textParameters, properFont, textBox);
	}

	private static FontMetrics getFontMetrics(Font font) {
		BufferedImage img = new BufferedImage(1, 1, BufferedImage.TYPE_INT_RGB);
		Graphics g = img.getGraphics();
		g.setFont(font);
		FontMetrics fontMetrics = g.getFontMetrics(font);
		g.dispose();
		return fontMetrics;
	}

	private static BufferedImage createTextImage(final SignatureImageTextParameters textParameters, final Font font,
			final AnnotationBox textBox) {
		String[] lines = textParameters.getText().split("\n");

		int imageType;
		if (isTransparent(textParameters.getTextColor(), textParameters.getBackgroundColor())) {
			LOG.warn("Transparency detected and enabled (Be aware: not valid with PDF/A !)");
			imageType = BufferedImage.TYPE_INT_ARGB;
		} else {
			imageType = BufferedImage.TYPE_INT_RGB;
		}

		BufferedImage img = new BufferedImage((int) textBox.getWidth(), (int) textBox.getHeight(), imageType);
		Graphics2D g = img.createGraphics();
		g.setFont(font);
		FontMetrics fm = g.getFontMetrics(font);

		// Improve text rendering
		CommonDrawerUtils.initRendering(g);

		if (textParameters.getBackgroundColor() == null) {
			g.setColor(Color.WHITE);
		} else {
			g.setColor(textParameters.getBackgroundColor());
		}
		g.fillRect(0, 0, (int) textBox.getWidth(), (int) textBox.getHeight());

		if (textParameters.getTextColor() == null) {
			g.setPaint(Color.BLACK);
		} else {
			g.setPaint(textParameters.getTextColor());
		}

		int lineHeight = fm.getHeight();
		float y = fm.getMaxAscent() + textParameters.getPadding();

		for (String line : lines) {
			float x = textParameters.getPadding(); // left alignment
			if (textParameters.getSignerTextHorizontalAlignment() != null) {
				switch (textParameters.getSignerTextHorizontalAlignment()) {
				case RIGHT:
					x = img.getWidth() - fm.stringWidth(line) - x; // -x because of margin
					break;
				case CENTER:
					x = (float) (img.getWidth() - fm.stringWidth(line)) / 2;
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
