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

import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.DSSFont;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.visible.DPIUtils;
import eu.europa.esig.dss.pdf.visible.ImageRotationUtils;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.pdf.visible.SignatureFieldDimensionAndPosition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.IOException;

/**
 * Contains the util methods used by the
 * {@code eu.europa.esig.dss.pdf.pdfbox.visible.defaultdrawer.DefaultPdfBoxVisibleSignatureDrawer}
 *
 */
public final class DefaultImageDrawerUtils {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultImageDrawerUtils.class);

    /**
     * Default constructor
     */
    private DefaultImageDrawerUtils() {
    }

    /**
     * Creates an image representing the specified text
     *
     * @param imageParameters {@link SignatureImageParameters} to use
     * @param dimensionAndPosition {@link SignatureFieldDimensionAndPosition}
     * @param fontMetrics {@link JavaDSSFontMetrics}
     * @return {@link BufferedImage} of the text picture
     */
    public static BufferedImage createTextImage(final SignatureImageParameters imageParameters,
                                                final SignatureFieldDimensionAndPosition dimensionAndPosition,
                                                final JavaDSSFontMetrics fontMetrics) {
        SignatureImageTextParameters textParameters = imageParameters.getTextParameters();
        String[] lines = dimensionAndPosition.getText().split("\n");

        int imageType;
        if (isTransparent(textParameters.getTextColor(), textParameters.getBackgroundColor())) {
            LOG.warn("Transparency detected and enabled (Be aware: not valid with PDF/A !)");
            imageType = BufferedImage.TYPE_INT_ARGB;
        } else {
            imageType = BufferedImage.TYPE_INT_RGB;
        }

        int textDPI = DPIUtils.getDpi(imageParameters.getDpi());
        BufferedImage img = new BufferedImage((int) DPIUtils.computeProperSize(dimensionAndPosition.getTextBoxWidth(), textDPI),
                (int) DPIUtils.computeProperSize(dimensionAndPosition.getTextBoxHeight(), textDPI), imageType);

        Graphics2D g = img.createGraphics();
        Font font = getJavaFont(imageParameters, dimensionAndPosition.getTextSize(), textDPI);
        g.setFont(font);

        // Improve text rendering
        initRendering(g);

        if (textParameters.getBackgroundColor() == null) {
            g.setColor(Color.WHITE);
        } else {
            g.setColor(textParameters.getBackgroundColor());
        }
        g.fillRect(0, 0, img.getWidth(), img.getHeight());

        if (textParameters.getTextColor() == null) {
            g.setPaint(Color.BLACK);
        } else {
            g.setPaint(textParameters.getTextColor());
        }

        float lineHeight = fontMetrics.getHeight(lines[0], font.getSize());
        float y = fontMetrics.getMaxAscent(font.getSize()) + DPIUtils.computeProperSize(
                dimensionAndPosition.getTextY() - dimensionAndPosition.getTextBoxY(), textDPI);

        for (String line : lines) {
            // left alignment by default
            float x = DPIUtils.computeProperSize(dimensionAndPosition.getTextX() - dimensionAndPosition.getTextBoxX(), textDPI);
            if (textParameters.getSignerTextHorizontalAlignment() != null) {
                switch (textParameters.getSignerTextHorizontalAlignment()) {
                    case RIGHT:
                        x = img.getWidth() - fontMetrics.getWidth(line, font.getSize()) - x; // -x because of margin
                        break;
                    case CENTER:
                        x = (img.getWidth() - fontMetrics.getWidth(line, font.getSize())) / 2;
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

    private static Font getJavaFont(SignatureImageParameters imageParameters, float textSize, int dpi) {
        DSSFont dssFont = imageParameters.getTextParameters().getFont();
        float fontSize = DPIUtils.computeProperSize(textSize, dpi);

        Font javaFont = dssFont.getJavaFont();
        return javaFont.deriveFont(fontSize);
    }

    private static boolean isTransparent(Color... colors) {
        if (colors != null) {
            for (Color color : colors) {
                if (color != null) {
                    int alpha = color.getAlpha();
                    if (alpha < 255) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Reads and converts the given image document to a {@code BufferedImage}
     *
     * @param imageDocument {@link BufferedImage}
     * @return {@link BufferedImage}
     */
    public static BufferedImage toBufferedImage(final DSSDocument imageDocument) {
        try {
            return ImageUtils.toBufferedImage(imageDocument);
        } catch (IOException e) {
            throw new IllegalInputException(String.format("An error occurred during image document reading : %s", e.getMessage()), e);
        }
    }

    /**
     * Sets the preferred image creation parameters to improve the rendering
     *
     * @param g {@link Graphics2D} to set
     */
    public static void initRendering(Graphics2D g) {
        g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_COLOR_RENDERING, RenderingHints.VALUE_COLOR_RENDER_QUALITY);
        g.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_ALPHA_INTERPOLATION, RenderingHints.VALUE_ALPHA_INTERPOLATION_QUALITY);
    }

    /**
     * Creates the final image, by merging the given {@code image} and {@code textImage}
     * according to the provided parameters
     *
     * @param image {@link BufferedImage} the image picture
     * @param textImage {@link BufferedImage} the rasterized text
     * @param dimensionAndPosition {@link SignatureFieldDimensionAndPosition}
     * @param imageParameters {@link SignatureImageParameters}
     * @return {@link BufferedImage}
     */
    public static BufferedImage mergeImages(BufferedImage image, BufferedImage textImage,
                                            SignatureFieldDimensionAndPosition dimensionAndPosition,
                                            SignatureImageParameters imageParameters) {
        final int imageType = getImageType(image, textImage);
        int xDpi = dimensionAndPosition.getImageResolution().getXDpi();
        int yDpi = dimensionAndPosition.getImageResolution().getYDpi();
        if (textImage != null) {
            xDpi = DPIUtils.getDpi(imageParameters.getDpi());
            yDpi = DPIUtils.getDpi(imageParameters.getDpi());
        }

        float imageWidthRatio = 1f;
        float imageHeightRatio = 1f;
        if (image != null) {
            float widthRatio = (image.getWidth() / dimensionAndPosition.getImageWidth()) * DPIUtils.getPageScaleFactor(xDpi);
            imageWidthRatio = widthRatio > 1 ? widthRatio : imageWidthRatio;
            float heightRatio = image.getHeight() / dimensionAndPosition.getImageHeight() * DPIUtils.getPageScaleFactor(yDpi);
            imageHeightRatio = heightRatio > 1 ? heightRatio : imageHeightRatio;
        }

        float width = dimensionAndPosition.getBoxWidth();
        float height = dimensionAndPosition.getBoxHeight();
        if (ImageRotationUtils.isSwapOfDimensionsRequired(dimensionAndPosition.getGlobalRotation())) {
            width =  dimensionAndPosition.getBoxHeight();
            height = dimensionAndPosition.getBoxWidth();
        }
        BufferedImage result = getEmptyImage(width * imageWidthRatio, height * imageHeightRatio, xDpi, yDpi, imageType);
        Graphics2D g = result.createGraphics();
        initRendering(g);

        // required for non-transparent and text containing pictures to avoid black spaces
        if (BufferedImage.TYPE_INT_ARGB != imageType ||
                imageParameters.getTextParameters() != null && !imageParameters.getTextParameters().isEmpty() ||
                imageParameters.getBackgroundColor() != null) {
            fillBackground(g, result.getWidth(), result.getHeight(), imageParameters.getBackgroundColor());
        }

        if (textImage != null) {
            drawImage(g, textImage, DPIUtils.computeProperSize(dimensionAndPosition.getTextBoxX() * imageWidthRatio, xDpi),
                    DPIUtils.computeProperSize((height - dimensionAndPosition.getTextBoxY() - dimensionAndPosition.getTextBoxHeight()) * imageHeightRatio, yDpi),
                    DPIUtils.computeProperSize(dimensionAndPosition.getTextBoxWidth() * imageWidthRatio, xDpi),
                    DPIUtils.computeProperSize(dimensionAndPosition.getTextBoxHeight() * imageHeightRatio, yDpi));
        }
        if (image != null) {
            drawImage(g, image, DPIUtils.computeProperSize(dimensionAndPosition.getImageX() * imageWidthRatio, xDpi),
                    DPIUtils.computeProperSize((height - dimensionAndPosition.getImageY() - dimensionAndPosition.getImageHeight()) * imageHeightRatio, yDpi),
                    DPIUtils.computeProperSize(dimensionAndPosition.getImageWidth() * imageWidthRatio, xDpi),
                    DPIUtils.computeProperSize(dimensionAndPosition.getImageHeight() * imageHeightRatio, yDpi));
        }
        return result;
    }

    private static int getImageType(final BufferedImage image1, final BufferedImage image2) {
        int imageType = BufferedImage.TYPE_INT_RGB;

        if ((image1 != null && ImageUtils.isTransparent(image1)) || (image2 != null && ImageUtils.isTransparent(image2))) {
            LOG.warn("Transparency detected and enabled (Be aware: not valid with PDF/A !)");
            imageType = BufferedImage.TYPE_INT_ARGB;
        }

        return imageType;
    }

    private static BufferedImage getEmptyImage(float width, float height, int xDpi, int yDpi, int imageType) {
        return new BufferedImage((int) DPIUtils.computeProperSize(width, xDpi),
               (int) DPIUtils.computeProperSize(height, yDpi), imageType);
    }

    private static void fillBackground(Graphics g, float width, float height, Color bgColor) {
        g.setColor(bgColor);
        g.fillRect(0, 0, (int) width, (int) height);
    }

    private static void drawImage(Graphics g, BufferedImage image, float x, float y, float width, float height) {
        g.drawImage(image, (int) x, (int) y,
                (int) width, (int) height, null);
    }

    /**
     * Rotates the provided image to the given {@code angle}
     *
     * @param image {@link BufferedImage} to rotate
     * @param angle the rotation angle
     * @return rotated {@link BufferedImage}
     */
    public static BufferedImage rotate(BufferedImage image, double angle) {
        if (ImageRotationUtils.ANGLE_0 == angle || ImageRotationUtils.ANGLE_360 == angle) {
            return image;
        }
        double sin = Math.abs(Math.sin(Math.toRadians(angle)));
        double cos = Math.abs(Math.cos(Math.toRadians(angle)));

        int w = image.getWidth();
        int h = image.getHeight();

        double neww = Math.floor(w * cos + h * sin);
        double newh = Math.floor(h * cos + w * sin);

        BufferedImage result = new BufferedImage((int) neww, (int) newh, image.getType());
        Graphics2D g = result.createGraphics();

        g.translate((neww - w) / 2, (newh - h) / 2);
        g.rotate(Math.toRadians(angle), (double) w / 2, (double) h / 2);
        g.drawRenderedImage(image, null);
        g.dispose();

        return result;
    }

}
