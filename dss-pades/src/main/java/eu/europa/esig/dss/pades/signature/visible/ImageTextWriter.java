/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
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

/**
 * This class allows to generate image with text
 *
 */
public final class ImageTextWriter {

    private static final int DEFAULT_MARGIN = 10;

    private ImageTextWriter() {
    }

    public static BufferedImage createTextImage(final String text, final Font font, final Color textColor, final Color bgColor, final int dpi) {
        // Computing image size depending of the font
        float fontSize = Math.round((font.getSize() * dpi) / 72.0);
        Font largerFont = font.deriveFont(fontSize);
        Dimension dimension = computeSize(largerFont, text);
        // gettters returns doubles ??
        return createTextImage(text, largerFont, textColor, bgColor, dimension.width, dimension.height);
    }

    public static Dimension computeSize(Font font, String text) {
        BufferedImage img = new BufferedImage(1, 1, BufferedImage.TYPE_INT_RGB);
        Graphics g = img.getGraphics();
        g.setFont(font);
        FontMetrics fontMetrics = g.getFontMetrics(font);

        String[] lines = text.split("\n");

        int width = 0;
        for (String line : lines) {
            int lineWidth = fontMetrics.stringWidth(line);
            if (lineWidth > width) {
                width = lineWidth;
            }
        }

        width += DEFAULT_MARGIN;
        int height = (fontMetrics.getHeight() + fontMetrics.getAscent()) * lines.length + DEFAULT_MARGIN;
        return new Dimension(width, height);
    }

    private static BufferedImage createTextImage(final String text, final Font font, final Color textColor, final Color bgColor, final int width,
                                                 final int height) {
        String[] lines = text.split("\n");

        BufferedImage img = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        g.setFont(font);
        FontMetrics fm = g.getFontMetrics(font);

        // Improve text rendering
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_COLOR_RENDERING, RenderingHints.VALUE_COLOR_RENDER_QUALITY);
        g.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

        g.setColor(bgColor);
        g.fillRect(0, 0, width, height);

        g.setPaint(textColor);

        int lineHeight = fm.getHeight() + fm.getAscent();
        int y = fm.getHeight() + fm.getAscent() / 2;

        for (String line : lines) {
            int x = img.getWidth() - fm.stringWidth(line) - (DEFAULT_MARGIN / 2);
            g.drawString(line, x, y);
            y += lineHeight;
        }
        g.dispose();

        return img;
    }

}
