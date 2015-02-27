package eu.europa.ec.markt.dss.signature.pades.visible;

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
