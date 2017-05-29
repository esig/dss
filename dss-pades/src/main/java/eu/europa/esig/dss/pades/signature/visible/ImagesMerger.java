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

import eu.europa.esig.dss.pades.SignatureImageParameters;

import java.awt.Color;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;

/**
 * This class allows to merge two pictures together
 *
 */
public final class ImagesMerger {

	private ImagesMerger() {
	}

	public static BufferedImage mergeOnTop(final BufferedImage bottom, final BufferedImage top, final Color bgColor) {
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

		ImageUtils.initRendering(g);
		fillBackground(g, newImageWidth, newImageHeigth, bgColor);

		g.drawImage(top, (newImageWidth - top.getWidth()) / 2, 0, top.getWidth(), top.getHeight(), null);
		g.drawImage(bottom, (newImageWidth - bottom.getWidth()) / 2, top.getHeight(), bottom.getWidth(), bottom.getHeight(), null);

		return combined;
	}

	public static BufferedImage mergeOnRight(final BufferedImage left, final BufferedImage right, final Color bgColor,
											 final SignatureImageParameters.SignerTextImageVerticalAlignment imageVerticalAlignment) {
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

		ImageUtils.initRendering(g);
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
				if(left.getHeight() > right.getHeight()) {
					g.drawImage(left, 0, 0, left.getWidth(), left.getHeight(), null);
					g.drawImage(right, left.getWidth(), newImageHeigth - right.getHeight(), right.getWidth(), right.getHeight(), null);
				} else {
					g.drawImage(left, 0, newImageHeigth - left.getHeight(), left.getWidth(), left.getHeight(), null);
					g.drawImage(right, left.getWidth(), 0, right.getWidth(), right.getHeight(), null);
				}
				break;
		}

		return combined;
	}

	private static void fillBackground(Graphics g, final int width, final int heigth, final Color bgColor) {
		g.setColor(bgColor);
		g.fillRect(0, 0, width, heigth);
	}

	private static int getImageType(final BufferedImage image1, final BufferedImage image2) {
		int imageType = BufferedImage.TYPE_INT_RGB;

		if(ImageUtils.isTransparent(image1) || ImageUtils.isTransparent(image2)) {
			imageType = BufferedImage.TYPE_INT_ARGB;
		}

		return imageType;
	}
}
