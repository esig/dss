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

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.imageio.ImageIO;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;

import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pdf.pdfbox.visible.ImageRotationUtils;
import eu.europa.esig.dss.pdf.visible.ImageAndResolution;
import eu.europa.esig.dss.pdf.visible.ImageUtils;

public final class SignatureImageAndPositionProcessor {

	private SignatureImageAndPositionProcessor() {
	}

    private static final String NOT_SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE = "not supported vertical alignment: ";
    private static final String NOT_SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE = "not supported horizontal alignment: ";

    public static SignatureImageAndPosition process(final SignatureImageParameters signatureImageParameters, 
    		final PDDocument doc, final ImageAndResolution ires) throws IOException {
		try (InputStream is = ires.getInputStream()) {
			
			BufferedImage visualImageSignature = ImageUtils.read(is);
			
			PDPage pdPage = doc.getPages().get(signatureImageParameters.getPage() - 1);

			int rotate = ImageRotationUtils.getRotation(signatureImageParameters.getRotation(), pdPage);
			if (rotate != ImageRotationUtils.ANGLE_360) {
				visualImageSignature = ImageUtils.rotate(visualImageSignature, rotate);
			}

			float x = processX(rotate, ires, visualImageSignature, pdPage, signatureImageParameters);
			float y = processY(rotate, ires, visualImageSignature, pdPage, signatureImageParameters);

			ByteArrayOutputStream visualImageSignatureOutputStream = new ByteArrayOutputStream();
			String imageType = "jpg";
			if (visualImageSignature.getColorModel().hasAlpha()) {
				imageType = "png";
			}
			ImageIO.write(visualImageSignature, imageType, visualImageSignatureOutputStream);

			return new SignatureImageAndPosition(x, y, visualImageSignatureOutputStream.toByteArray(), rotate);
		}
    }

    private static float processX(int rotation, ImageAndResolution ires, BufferedImage visualImageSignature, PDPage pdPage, SignatureImageParameters signatureImageParameters) {
        float x;
        
        PDRectangle pageBox = pdPage.getMediaBox();
        float width = getWidth(signatureImageParameters, visualImageSignature, ires, ImageRotationUtils.isSwapOfDimensionsRequired(rotation));

        switch (rotation) {
            case ImageRotationUtils.ANGLE_90:
                x = processXAngle90(pageBox, signatureImageParameters, width);
                break;
            case ImageRotationUtils.ANGLE_180:
                x = processXAngle180(pageBox, signatureImageParameters, width);
                break;
            case ImageRotationUtils.ANGLE_270:
                x = processXAngle270(pageBox, signatureImageParameters, width);
                break;
            case ImageRotationUtils.ANGLE_360:
                x = processXAngle360(pageBox, signatureImageParameters, width);
                break;
            default:
                throw new IllegalStateException(ImageRotationUtils.SUPPORTED_ANGLES_ERROR_MESSAGE);
        }

        return x;
    }

    private static float processY(int rotation, ImageAndResolution ires, BufferedImage visualImageSignature, PDPage pdPage, SignatureImageParameters signatureImageParameters) {
        float y;
        
        PDRectangle pageBox = pdPage.getMediaBox();
        float height = getHeight(signatureImageParameters, visualImageSignature, ires, ImageRotationUtils.isSwapOfDimensionsRequired(rotation));
        
        switch (rotation) {
            case ImageRotationUtils.ANGLE_90:
                y = processYAngle90(pageBox, signatureImageParameters, height);
                break;
            case ImageRotationUtils.ANGLE_180:
                y = processYAngle180(pageBox, signatureImageParameters, height);
                break;
            case ImageRotationUtils.ANGLE_270:
                y = processYAngle270(pageBox, signatureImageParameters, height);
                break;
            case ImageRotationUtils.ANGLE_360:
                y = processYAngle360(pageBox, signatureImageParameters, height);
                break;
            default:
                throw new IllegalStateException(ImageRotationUtils.SUPPORTED_ANGLES_ERROR_MESSAGE);
        }

        return y;
    }
    
    private static float getWidth(SignatureImageParameters signatureImageParameters, BufferedImage visualImageSignature, ImageAndResolution ires, boolean swapDimensions) {
        float width = swapDimensions ? signatureImageParameters.getHeight() : signatureImageParameters.getWidth();
        if (width == 0) {
        	width = visualImageSignature.getWidth();
        	width = swapDimensions ? ires.toYPoint(width) : ires.toXPoint(width);
        }
        return width;
    }
    
    private static float getHeight(SignatureImageParameters signatureImageParameters, BufferedImage visualImageSignature, ImageAndResolution ires, boolean swapDimensions) {
        float height = swapDimensions ? signatureImageParameters.getWidth() : signatureImageParameters.getHeight();
        if (height == 0) {
        	height = visualImageSignature.getHeight();
        	height = swapDimensions ? ires.toXPoint(height) : ires.toYPoint(height);
        }
        return height;
    }

    private static float processXAngle90(PDRectangle mediaBox, SignatureImageParameters signatureImageParameters, float width) {
        float x;

		VisualSignatureAlignmentVertical alignmentVertical = signatureImageParameters.getVisualSignatureAlignmentVertical();

        switch (alignmentVertical) {
            case TOP:
            case NONE:
                x = mediaBox.getWidth() - zoom(width, signatureImageParameters.getZoom()) - signatureImageParameters.getyAxis();
                break;
            case MIDDLE:
                x = (mediaBox.getWidth() - zoom(width, signatureImageParameters.getZoom())) / 2;
                break;
            case BOTTOM:
                x = signatureImageParameters.getyAxis();
                break;
            default:
                throw new IllegalStateException(NOT_SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical.name());
        }

        return x;
    }

    private static float processXAngle180(PDRectangle mediaBox, SignatureImageParameters signatureImageParameters, float width) {
        float x;

		VisualSignatureAlignmentHorizontal alignmentHorizontal = signatureImageParameters.getVisualSignatureAlignmentHorizontal();

        switch (alignmentHorizontal) {
            case LEFT:
            case NONE:
                x = mediaBox.getWidth() - zoom(width, signatureImageParameters.getZoom()) - signatureImageParameters.getxAxis();
                break;
            case CENTER:
                x = (mediaBox.getWidth() - zoom(width, signatureImageParameters.getZoom())) / 2;
                break;
            case RIGHT:
                x = signatureImageParameters.getxAxis();
                break;
            default:
                throw new IllegalStateException(NOT_SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal.name());
        }

        return x;
    }

    private static float processXAngle270(PDRectangle mediaBox, SignatureImageParameters signatureImageParameters, float width) {
        float x;

		VisualSignatureAlignmentVertical alignmentVertical = signatureImageParameters.getVisualSignatureAlignmentVertical();

        switch (alignmentVertical) {
            case TOP:
            case NONE:
                x = signatureImageParameters.getyAxis();
                break;
            case MIDDLE:
                x = (mediaBox.getWidth() - zoom(width, signatureImageParameters.getZoom())) / 2;
                break;
            case BOTTOM:
                x = mediaBox.getWidth() - zoom(width, signatureImageParameters.getZoom()) - signatureImageParameters.getyAxis();
                break;
            default:
                throw new IllegalStateException(NOT_SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical.name());
        }

        return x;
    }

    private static float processXAngle360(PDRectangle mediaBox, SignatureImageParameters signatureImageParameters, float width) {
        float x;

		VisualSignatureAlignmentHorizontal alignmentHorizontal = signatureImageParameters.getVisualSignatureAlignmentHorizontal();

        switch (alignmentHorizontal) {
            case LEFT:
            case NONE:
                x = signatureImageParameters.getxAxis();
                break;
            case CENTER:
                x = (mediaBox.getWidth() - zoom(width, signatureImageParameters.getZoom())) / 2;
                break;
            case RIGHT:
                x = mediaBox.getWidth() - zoom(width, signatureImageParameters.getZoom()) - signatureImageParameters.getxAxis();
                break;
            default:
                throw new IllegalStateException(NOT_SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal.name());
        }

        return x;
    }

    private static float processYAngle90(PDRectangle mediaBox, SignatureImageParameters signatureImageParameters, float height) {
        float y;

		VisualSignatureAlignmentHorizontal alignmentHorizontal = signatureImageParameters.getVisualSignatureAlignmentHorizontal();

        switch (alignmentHorizontal) {
            case LEFT:
            case NONE:
                y = signatureImageParameters.getxAxis();
                break;
            case CENTER:
                y = (mediaBox.getHeight() - zoom(height, signatureImageParameters.getZoom())) / 2;
                break;
            case RIGHT:
                y = mediaBox.getHeight() - zoom(height, signatureImageParameters.getZoom()) - signatureImageParameters.getxAxis();
                break;
            default:
                throw new IllegalStateException(NOT_SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal.name());
        }

        return y;
    }

    private static float processYAngle180(PDRectangle mediaBox, SignatureImageParameters signatureImageParameters, float height) {
        float y;

		VisualSignatureAlignmentVertical alignmentVertical = signatureImageParameters.getVisualSignatureAlignmentVertical();

        switch (alignmentVertical) {
            case TOP:
            case NONE:
                y = mediaBox.getHeight() - zoom(height, signatureImageParameters.getZoom()) - signatureImageParameters.getyAxis();
                break;
            case MIDDLE:
                y = (mediaBox.getHeight() - zoom(height, signatureImageParameters.getZoom())) / 2;
                break;
            case BOTTOM:
                y = signatureImageParameters.getyAxis();
                break;
            default:
                throw new IllegalStateException(NOT_SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical.name());
        }

        return y;
    }

    private static float processYAngle270(PDRectangle mediaBox, SignatureImageParameters signatureImageParameters, float height) {
        float y;

		VisualSignatureAlignmentHorizontal alignmentHorizontal = signatureImageParameters.getVisualSignatureAlignmentHorizontal();

        switch (alignmentHorizontal) {
            case LEFT:
            case NONE:
                y = mediaBox.getHeight() - zoom(height, signatureImageParameters.getZoom()) - signatureImageParameters.getxAxis();
                break;
            case CENTER:
                y = (mediaBox.getHeight() - zoom(height, signatureImageParameters.getZoom())) / 2;
                break;
            case RIGHT:
                y = signatureImageParameters.getxAxis();
                break;
            default:
                throw new IllegalStateException(NOT_SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal.name());
        }

        return y;
    }

    private static float processYAngle360(PDRectangle mediaBox, SignatureImageParameters signatureImageParameters, float height) {
        float y;

		VisualSignatureAlignmentVertical alignmentVertical = signatureImageParameters.getVisualSignatureAlignmentVertical();

        switch (alignmentVertical) {
            case TOP:
            case NONE:
                y = signatureImageParameters.getyAxis();
                break;
            case MIDDLE:
                y = (mediaBox.getHeight() - zoom(height, signatureImageParameters.getZoom())) / 2;
                break;
            case BOTTOM:
                y = mediaBox.getHeight() - zoom(height, signatureImageParameters.getZoom()) - signatureImageParameters.getyAxis();
                break;
            default:
                throw new IllegalStateException(NOT_SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical.name());
        }

        return y;
    }
    
    private static float zoom(float originalFloat, int zoom) {
        return originalFloat * zoom / 100;
    }

}
