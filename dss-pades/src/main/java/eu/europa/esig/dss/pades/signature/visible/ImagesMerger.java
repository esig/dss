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
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
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

		BufferedImage combined = new BufferedImage(newImageWidth, newImageHeigth, top.getType());
		Graphics2D g = combined.createGraphics();

		initRendering(g);
		fillBackground(g, newImageWidth, newImageHeigth, bgColor);

		g.drawImage(top, (newImageWidth - top.getWidth()) / 2, 0, top.getWidth(), top.getHeight(), null);
		g.drawImage(bottom, (newImageWidth - bottom.getWidth()) / 2, top.getHeight(), bottom.getWidth(), bottom.getHeight(), null);

		return combined;
	}

	public static BufferedImage mergeOnRight(final BufferedImage left, final BufferedImage right, final Color bgColor) {
		if (left == null) {
			return right;
		} else if (right == null) {
			return left;
		}

		final int newImageWidth = left.getWidth() + right.getWidth();
		final int newImageHeigth = Math.max(left.getHeight(), right.getHeight());

		BufferedImage combined = new BufferedImage(newImageWidth, newImageHeigth, left.getType());
		Graphics2D g = combined.createGraphics();

		initRendering(g);
		fillBackground(g, newImageWidth, newImageHeigth, bgColor);

		g.drawImage(left, 0, (newImageHeigth - left.getHeight()) / 2, left.getWidth(), left.getHeight(), null);
		g.drawImage(right, left.getWidth(), (newImageHeigth - right.getHeight()) / 2, right.getWidth(), right.getHeight(), null);

		return combined;
	}

	private static void initRendering(Graphics2D g) {
		g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
		g.setRenderingHint(RenderingHints.KEY_COLOR_RENDERING, RenderingHints.VALUE_COLOR_RENDER_QUALITY);
		g.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
		g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);

	}

	private static void fillBackground(Graphics g, final int width, final int heigth, final Color bgColor) {
		g.setColor(bgColor);
		g.fillRect(0, 0, width, heigth);
	}

}
