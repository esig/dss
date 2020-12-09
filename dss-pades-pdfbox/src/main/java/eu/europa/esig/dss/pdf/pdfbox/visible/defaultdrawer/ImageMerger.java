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

import eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.enumerations.SignerTextVerticalAlignment;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pdf.visible.CommonDrawerUtils;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.*;
import java.awt.image.BufferedImage;

/**
 * This class allows to merge two pictures together
 *
 */
public final class ImageMerger {

	private static final Logger LOG = LoggerFactory.getLogger(ImageMerger.class);

	private ImageMerger() {
	}

	/**
	 * Creates a joined image between {@code bottom} and {@code top}
	 *
	 * @param bottom {@link BufferedImage} to place in the bottom
	 * @param top {@link BufferedImage} to place in the top
	 * @param bgColor {@link Color} the background color
	 * @param imageHorizontalAlignment {@link SignerTextHorizontalAlignment}
	 * @return {@link BufferedImage}
	 */
	public static BufferedImage mergeOnTop(final BufferedImage bottom, final BufferedImage top, final Color bgColor,
			final SignerTextHorizontalAlignment imageHorizontalAlignment) {
		if (bottom == null) {
			return top;
		} else if (top == null) {
			return bottom;
		}

		final int newImageWidth = Math.max(bottom.getWidth(), top.getWidth());
		final int newImageHeigth = bottom.getHeight() + top.getHeight();
		final int imageType = getImageType(bottom, top);

		BufferedImage combined = new BufferedImage(newImageWidth, newImageHeigth, imageType);
		Graphics2D g = combined.createGraphics();

		CommonDrawerUtils.initRendering(g);
		fillBackground(g, newImageWidth, newImageHeigth, bgColor);

		switch (imageHorizontalAlignment) {
			case LEFT:
				g.drawImage(bottom, 0, top.getHeight(), bottom.getWidth(), bottom.getHeight(), null);
				g.drawImage(top, 0, 0, top.getWidth(), top.getHeight(), null);
				break;
			case CENTER:
				g.drawImage(bottom, (newImageWidth - bottom.getWidth()) / 2, top.getHeight(), bottom.getWidth(), bottom.getHeight(), null);
				g.drawImage(top, (newImageWidth - top.getWidth()) / 2, 0, top.getWidth(), top.getHeight(), null);
				break;
			case RIGHT:
				g.drawImage(bottom, newImageWidth - bottom.getWidth(), top.getHeight(), bottom.getWidth(), bottom.getHeight(), null);
				g.drawImage(top, newImageWidth - top.getWidth(), 0, top.getWidth(), top.getHeight(), null);
				break;
			default:
				throw new DSSException("Unsupported SignerTextImageVerticalAlignment : " + imageHorizontalAlignment);
		}

		return combined;
	}

	/**
	 * Creates a joined image between {@code left} and {@code right}
	 *
	 * @param left {@link BufferedImage} to place in the left
	 * @param right {@link BufferedImage} to place in the right
	 * @param bgColor {@link Color} the background color
	 * @param imageVerticalAlignment {@link SignerTextVerticalAlignment}
	 * @return {@link BufferedImage}
	 */
	public static BufferedImage mergeOnRight(final BufferedImage left, final BufferedImage right, final Color bgColor,
			final SignerTextVerticalAlignment imageVerticalAlignment) {
		if (left == null) {
			return right;
		} else if (right == null) {
			return left;
		}

		final int newImageWidth = left.getWidth() + right.getWidth();
		final int newImageHeigth = Math.max(left.getHeight(), right.getHeight());
		final int imageType = getImageType(left, right);

		BufferedImage combined = new BufferedImage(newImageWidth, newImageHeigth, imageType);
		Graphics2D g = combined.createGraphics();

		CommonDrawerUtils.initRendering(g);
		fillBackground(g, newImageWidth, newImageHeigth, bgColor);

		switch (imageVerticalAlignment) {
			case TOP:
				g.drawImage(left, 0, 0, left.getWidth(), left.getHeight(), null);
				g.drawImage(right, left.getWidth(), 0, right.getWidth(), right.getHeight(), null);
				break;
			case MIDDLE:
				g.drawImage(left, 0, (newImageHeigth - left.getHeight()) / 2, left.getWidth(), left.getHeight(), null);
				g.drawImage(right, left.getWidth(), (newImageHeigth - right.getHeight()) / 2, right.getWidth(), right.getHeight(), null);
				break;
			case BOTTOM:
				g.drawImage(left, 0, newImageHeigth - left.getHeight(), left.getWidth(), left.getHeight(), null);
				g.drawImage(right, left.getWidth(), newImageHeigth - right.getHeight(), right.getWidth(), right.getHeight(), null);
				break;
			default:
				throw new DSSException("Unsupported SignerTextImageVerticalAlignment : " + imageVerticalAlignment);
		}

		return combined;
	}

	private static void fillBackground(Graphics g, final int width, final int heigth, final Color bgColor) {
		g.setColor(bgColor);
		g.fillRect(0, 0, width, heigth);
	}

	private static int getImageType(final BufferedImage image1, final BufferedImage image2) {
		int imageType = BufferedImage.TYPE_INT_RGB;

		if (ImageUtils.isTransparent(image1) || ImageUtils.isTransparent(image2)) {
			LOG.warn("Transparency detected and enabled (Be aware: not valid with PDF/A !)");
			imageType = BufferedImage.TYPE_INT_ARGB;
		}

		return imageType;
	}
}
