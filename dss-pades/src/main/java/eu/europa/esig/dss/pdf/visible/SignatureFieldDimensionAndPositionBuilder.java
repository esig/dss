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
package eu.europa.esig.dss.pdf.visible;

import eu.europa.esig.dss.enumerations.ImageScaling;
import eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.enumerations.SignerTextVerticalAlignment;
import eu.europa.esig.dss.enumerations.TextWrapping;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds a {@code SignatureFieldDimensionAndPosition} for visual signature creation
 *
 */
public class SignatureFieldDimensionAndPositionBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(SignatureFieldDimensionAndPositionBuilder.class);

    /** An error message for an unsupported vertical alignment */
    private static final String NOT_SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE = "not supported vertical alignment: ";
    /** An error message for an unsupported horizontal alignment */
    private static final String NOT_SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE = "not supported horizontal alignment: ";

    private static final int DEFAULT_DPI = DPIUtils.getDpi(null);

    /** Visual signature parameters */
    protected final SignatureImageParameters imageParameters;

    /** The font metrics */
    private final DSSFontMetrics fontMetrics;

    /** The page's rotation value */
    private final int pageRotation;

    /** The page rectangle */
    private AnnotationBox pageBox;

    /** The annotation box representing a target signature field dimensions when applicable */
    private AnnotationBox signatureFieldAnnotationBox;

    /** Cached {@code SignatureFieldDimensionAndPosition} */
    private SignatureFieldDimensionAndPosition dimensionAndPosition;

    /**
     * Default constructor
     *
     * @param imageParameters {@link SignatureImageParameters}
     * @param fontMetrics {@link DSSFontMetrics}
     * @param pageBox {@link AnnotationBox} defining the page's dimensions
     * @param pageRotation page rotation value
     */
    public SignatureFieldDimensionAndPositionBuilder(final SignatureImageParameters imageParameters,
                                                     final DSSFontMetrics fontMetrics,
                                                     final AnnotationBox pageBox,
                                                     final int pageRotation) {
        this.imageParameters = imageParameters;
        this.fontMetrics = fontMetrics;
        this.pageBox = pageBox;
        this.pageRotation = pageRotation;
    }

    /**
     * This method sets the target annotation box to wrap the signature representation into
     *
     * @param signatureFieldAnnotationBox {@link AnnotationBox}
     * @return this {@link SignatureFieldDimensionAndPositionBuilder}
     */
    public SignatureFieldDimensionAndPositionBuilder setSignatureFieldAnnotationBox(AnnotationBox signatureFieldAnnotationBox) {
        this.signatureFieldAnnotationBox = signatureFieldAnnotationBox;
        return this;
    }

    /**
     * Builds the {@code SignatureFieldDimensionAndPosition}
     *
     * @return {@link SignatureFieldDimensionAndPosition}
     */
    public SignatureFieldDimensionAndPosition build() {
        assertConfigurationValid();
        if (dimensionAndPosition == null) {
            dimensionAndPosition = new SignatureFieldDimensionAndPosition(pageBox);
            initDpi();
            initRotation();
            assignImageBoundaryBox();
            assignImagePosition();
            alignHorizontally();
            alignVertically();
            rotateSignatureField();
        }
        return dimensionAndPosition;
    }

    private void initDpi() {
        ImageResolution imageResolution;
        if (imageParameters.getImage() != null) {
            try {
                imageResolution = ImageUtils.secureReadMetadata(imageParameters);
            } catch (Exception e) {
                LOG.warn("Cannot access the image metadata : {}. Returns default info.", e.getMessage());
                imageResolution = new ImageResolution(imageParameters.getDpi(), imageParameters.getDpi());
            }
        } else {
            imageResolution = new ImageResolution(DEFAULT_DPI, DEFAULT_DPI);
        }
        dimensionAndPosition.setImageResolution(imageResolution);
    }

    private void initRotation() {
        SignatureFieldParameters fieldParameters = imageParameters.getFieldParameters();
        int rotation = ImageRotationUtils.getRotation(fieldParameters.getRotation(), pageRotation);
        dimensionAndPosition.setGlobalRotation(rotation);
        if (ImageRotationUtils.isSwapOfDimensionsRequired(rotation)) {
            pageBox = ImageRotationUtils.swapDimensions(pageBox);
        }
    }

    private void assignImageBoundaryBox() {
        AnnotationBox imageBoundaryBox = getSignatureFieldBoundaryBox();
        float imageWidth = imageBoundaryBox.getWidth();
        float imageHeight = imageBoundaryBox.getHeight();

        float width = imageWidth;
        float height = imageHeight;

        SignatureFieldParameters fieldParameters = imageParameters.getFieldParameters();
        SignatureImageTextParameters textParameters = imageParameters.getTextParameters();
        // if text is present
        if (textParameters != null && !textParameters.isEmpty()) {
            if (fontMetrics == null) {
                throw new NullPointerException("DSSFontMetrics shall be defined!");
            }

            float padding = textParameters.getPadding();
            float properTextSize = textParameters.getFont().getSize() * ImageUtils.getScaleFactor(imageParameters.getZoom());
            // native implementation uses dpi-independent font
            final AnnotationBox estimatedTextBox = computeTextBox(textParameters, width, height, padding, properTextSize);
            TextFitter.Result fitResult = TextFitter.fitSignatureText(textParameters, properTextSize, fontMetrics, estimatedTextBox);
            dimensionAndPosition.setText(fitResult.getText());
            dimensionAndPosition.setTextSize(fitResult.getSize());

            final AnnotationBox textBox = fontMetrics.computeTextBoundaryBox(fitResult.getText(), fitResult.getSize());
            float textHeight = Math.min(textBox.getHeight(), estimatedTextBox.getHeight());
            float textWidth = Math.min(textBox.getWidth(), estimatedTextBox.getWidth());
            textHeight += padding * 2;
            textWidth += padding * 2;

            switch (textParameters.getSignerTextPosition()) {
                case LEFT:
                    if (fieldParameters.getWidth() == 0) {
                        width += imageParameters.getImage() != null || width == 0 ? textWidth : 0;
                    } else {
                        imageWidth -= imageParameters.getImage() != null || width == 0 ? textWidth : 0;
                    }
                    if (fieldParameters.getHeight() == 0) {
                        height = Math.max(height, textHeight);
                    }
                    dimensionAndPosition.setImageBoxX(width - imageWidth);
                    textImageVerticalAlignment(height, imageHeight, textHeight);
                    break;
                case RIGHT:
                    if (fieldParameters.getWidth() == 0) {
                        width += imageParameters.getImage() != null || width == 0 ? textWidth : 0;
                    } else {
                        imageWidth -= imageParameters.getImage() != null || width == 0 ? textWidth : 0;
                    }
                    if (fieldParameters.getHeight() == 0) {
                        height = Math.max(height, textHeight);
                    }
                    dimensionAndPosition.setTextBoxX(width - textWidth);
                    textImageVerticalAlignment(height, imageHeight, textHeight);
                    break;
                case TOP:
                    if (fieldParameters.getWidth() == 0) {
                        width = Math.max(width, textWidth);
                    }
                    if (fieldParameters.getHeight() == 0) {
                        height += imageParameters.getImage() != null || height == 0 ? textHeight : 0;
                    } else {
                        imageHeight -= imageParameters.getImage() != null || height == 0 ? textHeight : 0;
                    }
                    dimensionAndPosition.setTextBoxY(height - textHeight);
                    textImageHorizontalAlignment(width, imageWidth, textWidth);
                    break;
                case BOTTOM:
                    if (fieldParameters.getWidth() == 0) {
                        width = Math.max(width, textWidth);
                    }
                    if (fieldParameters.getHeight() == 0) {
                        height += imageParameters.getImage() != null || height == 0 ? textHeight : 0;
                    } else {
                        imageHeight -= imageParameters.getImage() != null || height == 0 ? textHeight : 0;
                    }
                    dimensionAndPosition.setImageBoxY(height - imageHeight);
                    textImageHorizontalAlignment(width, imageWidth, textWidth);
                    break;
                default:
                    break;
            }

            dimensionAndPosition.setTextBoxWidth(textWidth);
            dimensionAndPosition.setTextBoxHeight(textHeight);

            dimensionAndPosition.setTextX(dimensionAndPosition.getTextBoxX() + padding);
            dimensionAndPosition.setTextY(dimensionAndPosition.getTextBoxY() + padding);
            dimensionAndPosition.setTextWidth(dimensionAndPosition.getTextBoxWidth() - 2 * padding);
            dimensionAndPosition.setTextHeight(dimensionAndPosition.getTextBoxHeight() - 2 * padding);
        }

        if (ImageRotationUtils.isSwapOfDimensionsRequired(dimensionAndPosition.getGlobalRotation())) {
            float temp = width;
            width = height;
            height = temp;
        }

        dimensionAndPosition.setImageBoxWidth(imageWidth);
        dimensionAndPosition.setImageBoxHeight(imageHeight);
        dimensionAndPosition.setBoxWidth(width);
        dimensionAndPosition.setBoxHeight(height);
    }

    /**
     * Returns the signature field boundary box based on the parameters or/and provided image
     *
     * @return {@link AnnotationBox}
     */
    private AnnotationBox getSignatureFieldBoundaryBox() {
        float width;
        float height;
        if (signatureFieldAnnotationBox != null) {
            width = signatureFieldAnnotationBox.getWidth();
            height = signatureFieldAnnotationBox.getHeight();
            if (ImageRotationUtils.isSwapOfDimensionsRequired(dimensionAndPosition.getGlobalRotation())) {
                width = signatureFieldAnnotationBox.getHeight();
                height = signatureFieldAnnotationBox.getWidth();
            }
        } else {
            SignatureFieldParameters fieldParameters = imageParameters.getFieldParameters();
            width = fieldParameters.getWidth();
            height = fieldParameters.getHeight();
        }

        float scaleFactor = ImageUtils.getScaleFactor(imageParameters.getZoom());
        DSSDocument docImage = imageParameters.getImage();
        if (docImage != null) {
            AnnotationBox imageBoundaryBox = ImageUtils.getImageBoundaryBox(docImage);
            dimensionAndPosition.setImageWidth(imageBoundaryBox.getWidth() * scaleFactor);
            dimensionAndPosition.setImageHeight(imageBoundaryBox.getHeight() * scaleFactor);
            if (width == 0) {
                width = imageBoundaryBox.getWidth();
                width *= DPIUtils.getPageScaleFactor(dimensionAndPosition.getImageResolution().getXDpi());
            }
            if (height == 0) {
                height = imageBoundaryBox.getHeight();
                height *= DPIUtils.getPageScaleFactor(dimensionAndPosition.getImageResolution().getYDpi());
            }
        }
        width *= scaleFactor;
        height *= scaleFactor;

        return new AnnotationBox(0, 0, width, height);
    }

    private AnnotationBox computeTextBox(SignatureImageTextParameters textParameters,
                                         float width, float height, float padding, float fontSize) throws IllegalArgumentException {
        switch (textParameters.getTextWrapping()) {
            case FILL_BOX:
            case FILL_BOX_AND_LINEBREAK:
                return computeAutoFitTextDimensions(textParameters, width, height, padding);
            case FONT_BASED:
                return computeTextDimension(textParameters.getText(), fontSize);
            default:
                throw new IllegalArgumentException(String.format("The TextWrapping '%s' is not supported!",
                        textParameters.getTextWrapping()));
        }
    }
    
    /**
     * Attempts to fit the signature's text content into as much of the available signature box as possible
     * and returns the corresponding text box.
     *
     * @param textParameters the signature's text parameters, text content and font size will be modified
     * @param width the width of the signature box
     * @param height the height of the signature box
     * @param padding the padding of the text box
     * @return the computed text box using the updated text content and font size
     * @throws IllegalArgumentException if an unsupported signer text position is supplied
     */
    private AnnotationBox computeAutoFitTextDimensions(SignatureImageTextParameters textParameters,
                                                       float width, float height, float padding) throws IllegalArgumentException {
        float doublePadding = 2 * padding;

        float boxWidth = width - doublePadding;
        float boxHeight = height - doublePadding;
        if (imageParameters.getImage() != null) {
            float imageWidth = dimensionAndPosition.getImageWidth();
            float imageHeight = dimensionAndPosition.getImageHeight();
            switch (imageParameters.getImageScaling()) {
                case STRETCH:
                case CENTER:
                    // additional logic is not required
                    break;
                case ZOOM_AND_CENTER:
                    float imageRatio = imageWidth / imageHeight;
                    float boxRatio = width / height;
                    if (imageRatio < boxRatio) {
                        imageWidth = height * imageRatio;
                        imageHeight = height;
                    } else {
                        imageWidth = width;
                        imageHeight = width / imageRatio;
                    }
                    break;
                default:
                    throw new UnsupportedOperationException(
                            String.format("ImageScaling '%s' is not implemented!", imageParameters.getImageScaling()));
            }

            switch (textParameters.getSignerTextPosition()) {
                case LEFT:
                case RIGHT:
                    boxWidth = width - imageWidth - doublePadding;
                    break;
                case TOP:
                case BOTTOM:
                    boxHeight = height - imageHeight - doublePadding;
                    break;
                default:
                    throw new IllegalArgumentException(String.format("The SignerTextPosition '%s' is not supported!",
                            textParameters.getSignerTextPosition()));
            }
        }
        if (boxWidth <= 0 || boxHeight <= 0) {
            throw new IllegalArgumentException("Unable to create a visual signature. The signature field box is too small!");
        }

        return new AnnotationBox(0, 0, boxWidth, boxHeight);
    }

    private AnnotationBox computeTextDimension(String text, float fontSize) {
        return fontMetrics.computeTextBoundaryBox(text, fontSize);
    }

    private void textImageVerticalAlignment(float height, float imageHeight, float textHeight) {
        SignerTextVerticalAlignment verticalAlignment = imageParameters.getTextParameters()
                .getSignerTextVerticalAlignment();
        switch (verticalAlignment) {
            case TOP:
                dimensionAndPosition.setTextBoxY(height - textHeight);
                dimensionAndPosition.setImageBoxY(height - imageHeight);
                break;
            case BOTTOM:
                dimensionAndPosition.setTextBoxY(0);
                dimensionAndPosition.setImageBoxY(0);
                break;
            case MIDDLE:
                dimensionAndPosition.setTextBoxY((height - textHeight) / 2);
                dimensionAndPosition.setImageBoxY((height - imageHeight) / 2);
                break;
            default:
                throw new IllegalStateException(NOT_SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + verticalAlignment);
        }
    }

    private void textImageHorizontalAlignment(float width, float imageWidth, float textWidth) {
        SignerTextHorizontalAlignment horizontalAlignment = imageParameters.getTextParameters()
                .getSignerTextHorizontalAlignment();
        switch (horizontalAlignment) {
            case LEFT:
                dimensionAndPosition.setTextBoxX(0);
                dimensionAndPosition.setImageBoxX(0);
                break;
            case RIGHT:
                dimensionAndPosition.setTextBoxX(width - textWidth);
                dimensionAndPosition.setImageBoxX(width - imageWidth);
                break;
            case CENTER:
                dimensionAndPosition.setTextBoxX((width - textWidth) / 2);
                dimensionAndPosition.setImageBoxX((width - imageWidth) / 2);
                break;
            default:
                throw new IllegalStateException(NOT_SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + horizontalAlignment);
        }
    }

    private void assignImagePosition() {
        if (imageParameters.getImage() != null) {
            switch (imageParameters.getImageScaling()) {
                case STRETCH:
                    dimensionAndPosition.setImageX(dimensionAndPosition.getImageBoxX());
                    dimensionAndPosition.setImageY(dimensionAndPosition.getImageBoxY());
                    dimensionAndPosition.setImageWidth(dimensionAndPosition.getImageBoxWidth());
                    dimensionAndPosition.setImageHeight(dimensionAndPosition.getImageBoxHeight());
                    break;

                case ZOOM_AND_CENTER:
                    float x;
                    float y;
                    float width;
                    float height;

                    float imageRatio = dimensionAndPosition.getImageWidth() / dimensionAndPosition.getImageHeight();
                    float boxRatio = dimensionAndPosition.getImageBoxWidth() / dimensionAndPosition.getImageBoxHeight();
                    if (imageRatio < boxRatio) {
                        width = dimensionAndPosition.getImageBoxHeight() * imageRatio;
                        height = dimensionAndPosition.getImageBoxHeight();
                        x = dimensionAndPosition.getImageBoxX() + (dimensionAndPosition.getImageBoxWidth() - width) / 2f;
                        y = dimensionAndPosition.getImageBoxY();
                    } else {
                        width = dimensionAndPosition.getImageBoxWidth();
                        height = dimensionAndPosition.getImageBoxWidth() / imageRatio;
                        x = dimensionAndPosition.getImageBoxX();
                        y = dimensionAndPosition.getImageBoxY() + (dimensionAndPosition.getImageBoxHeight() - height) / 2f;
                    }
                    dimensionAndPosition.setImageX(x);
                    dimensionAndPosition.setImageY(y);
                    dimensionAndPosition.setImageWidth(width);
                    dimensionAndPosition.setImageHeight(height);
                    break;

                case CENTER:
                    dimensionAndPosition.setImageX(dimensionAndPosition.getImageBoxX() +
                            (dimensionAndPosition.getImageBoxWidth() - dimensionAndPosition.getImageWidth()) / 2f);
                    dimensionAndPosition.setImageY(dimensionAndPosition.getImageBoxY() +
                            (dimensionAndPosition.getImageBoxHeight() - dimensionAndPosition.getImageHeight()) / 2f);
                    break;

                default:
                    throw new IllegalArgumentException(String.format("The ImageScaling '%s' is not supported!",
                            imageParameters.getImageScaling()));
            }
        }
    }

    private void alignHorizontally() {
        float boxWidth = dimensionAndPosition.getBoxWidth();
        if (ImageRotationUtils.isSwapOfDimensionsRequired(dimensionAndPosition.getGlobalRotation())) {
            boxWidth = dimensionAndPosition.getBoxHeight();
        }
        float boxX;
        SignatureFieldParameters fieldParameters = imageParameters.getFieldParameters();

        VisualSignatureAlignmentHorizontal alignmentHorizontal = imageParameters
                .getVisualSignatureAlignmentHorizontal();
        switch (alignmentHorizontal) {
            case LEFT:
            case NONE:
                boxX = fieldParameters.getOriginX();
                break;
            case CENTER:
                boxX = (pageBox.getWidth() - boxWidth) / 2;
                break;
            case RIGHT:
                boxX = pageBox.getWidth() - boxWidth - fieldParameters.getOriginX();
                break;
            default:
                throw new IllegalStateException(NOT_SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal);
        }
        dimensionAndPosition.setBoxX(boxX);
    }

    private void alignVertically() {
        float boxHeight = dimensionAndPosition.getBoxHeight();
        if (ImageRotationUtils.isSwapOfDimensionsRequired(dimensionAndPosition.getGlobalRotation())) {
            boxHeight = dimensionAndPosition.getBoxWidth();
        }
        float boxY;
        SignatureFieldParameters fieldParameters = imageParameters.getFieldParameters();

        VisualSignatureAlignmentVertical alignmentVertical = imageParameters.getVisualSignatureAlignmentVertical();
        switch (alignmentVertical) {
            case TOP:
            case NONE:
                boxY = fieldParameters.getOriginY();
                break;
            case MIDDLE:
                boxY = (pageBox.getHeight() - boxHeight) / 2;
                break;
            case BOTTOM:
                boxY = pageBox.getHeight() - boxHeight - fieldParameters.getOriginY();
                break;
            default:
                throw new IllegalStateException(NOT_SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical);
        }
        dimensionAndPosition.setBoxY(boxY);
    }

    private void rotateSignatureField() {
        switch (dimensionAndPosition.getGlobalRotation()) {
            case ImageRotationUtils.ANGLE_90:
                float boxX = dimensionAndPosition.getBoxX();
                dimensionAndPosition.setBoxX(
                        pageBox.getHeight() - dimensionAndPosition.getBoxY() - dimensionAndPosition.getBoxWidth());
                dimensionAndPosition.setBoxY(boxX);
                break;
            case ImageRotationUtils.ANGLE_180:
                dimensionAndPosition.setBoxX(
                        pageBox.getWidth() - dimensionAndPosition.getBoxX() - dimensionAndPosition.getBoxWidth());
                dimensionAndPosition.setBoxY(
                        pageBox.getHeight() - dimensionAndPosition.getBoxY() - dimensionAndPosition.getBoxHeight());
                break;
            case ImageRotationUtils.ANGLE_270:
                boxX = dimensionAndPosition.getBoxX();
                dimensionAndPosition.setBoxX(dimensionAndPosition.getBoxY());
                dimensionAndPosition.setBoxY(pageBox.getWidth() - boxX - dimensionAndPosition.getBoxHeight());
                break;
            case ImageRotationUtils.ANGLE_360:
            case ImageRotationUtils.ANGLE_0:
                // do nothing
                break;
            default:
                throw new IllegalStateException(ImageRotationUtils.SUPPORTED_ANGLES_ERROR_MESSAGE);
        }
    }

    private void assertConfigurationValid() {
        if (Utils.isStringNotEmpty(imageParameters.getTextParameters().getText())) {
            TextWrapping textWrapping = imageParameters.getTextParameters().getTextWrapping();
            if (TextWrapping.FILL_BOX.equals(textWrapping) || TextWrapping.FILL_BOX_AND_LINEBREAK.equals(textWrapping)) {
                if ((signatureFieldAnnotationBox == null || signatureFieldAnnotationBox.getWidth() == 0 || signatureFieldAnnotationBox.getHeight() == 0) &&
                        (imageParameters.getFieldParameters() == null || imageParameters.getFieldParameters().getWidth() == 0 || imageParameters.getFieldParameters().getHeight() == 0)) {
                    throw new IllegalArgumentException(String.format("Signature field dimensions are not defined! " +
                            "Unable to use '%s' option.", imageParameters.getTextParameters().getTextWrapping()));
                }
                if (imageParameters.getImage() != null && ImageScaling.STRETCH.equals(imageParameters.getImageScaling())) {
                    throw new IllegalArgumentException(String.format("ImageScaling '%s' is not applicable with text wrapping '%s' option!",
                            imageParameters.getImageScaling(), textWrapping));
                }
            }
        }
    }

}
