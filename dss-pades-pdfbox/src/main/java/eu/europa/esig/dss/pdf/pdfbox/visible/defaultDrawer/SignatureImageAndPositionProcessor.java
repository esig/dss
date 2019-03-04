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
package eu.europa.esig.dss.pdf.pdfbox.visible.defaultDrawer;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.imageio.ImageIO;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;

import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pdf.pdfbox.visible.ImageRotationUtils;
import eu.europa.esig.dss.pdf.pdfbox.visible.ImageUtils;
import eu.europa.esig.dss.pdf.visible.ImageAndResolution;

public final class SignatureImageAndPositionProcessor {

	private SignatureImageAndPositionProcessor() {
	}

    private static final String SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE = "not supported vertical alignment: ";
    private static final String SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE = "not supported horizontal alignment: ";

    public static SignatureImageAndPosition process(final SignatureImageParameters signatureImageParameters, final PDDocument doc, final ImageAndResolution ires) throws IOException {
		try (InputStream is = ires.getInputStream()) {
			BufferedImage visualImageSignature = ImageIO.read(is);
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

			return new SignatureImageAndPosition(x, y, visualImageSignatureOutputStream.toByteArray());
		}
    }

    private static float processX(int rotate, ImageAndResolution ires, BufferedImage visualImageSignature, PDPage pdPage, SignatureImageParameters signatureImageParameters) {
        float x;

        PDRectangle mediaBox = pdPage.getMediaBox();

        switch (rotate) {
            case ImageRotationUtils.ANGLE_90:
                x = processXAngle90(mediaBox, ires, signatureImageParameters, visualImageSignature);
                break;
            case ImageRotationUtils.ANGLE_180:
                x = processXAngle180(mediaBox, ires, signatureImageParameters, visualImageSignature);
                break;
            case ImageRotationUtils.ANGLE_270:
                x = processXAngle270(mediaBox, ires, signatureImageParameters, visualImageSignature);
                break;
            case ImageRotationUtils.ANGLE_360:
                x = processXAngle360(mediaBox, ires, signatureImageParameters, visualImageSignature);
                break;
            default:
                throw new IllegalStateException(ImageRotationUtils.SUPPORTED_ANGLES_ERROR_MESSAGE);
        }

        return x;
    }

    private static float processY(int rotate, ImageAndResolution ires, BufferedImage visualImageSignature, PDPage pdPage, SignatureImageParameters signatureImageParameters) {
        float y;

        PDRectangle mediaBox = pdPage.getMediaBox();

        switch (rotate) {
            case ImageRotationUtils.ANGLE_90:
                y = processYAngle90(mediaBox, ires, signatureImageParameters, visualImageSignature);
                break;
            case ImageRotationUtils.ANGLE_180:
                y = processYAngle180(mediaBox, ires, signatureImageParameters, visualImageSignature);
                break;
            case ImageRotationUtils.ANGLE_270:
                y = processYAngle270(mediaBox, ires, signatureImageParameters, visualImageSignature);
                break;
            case ImageRotationUtils.ANGLE_360:
                y = processYAngle360(mediaBox, ires, signatureImageParameters, visualImageSignature);
                break;
            default:
                throw new IllegalStateException(ImageRotationUtils.SUPPORTED_ANGLES_ERROR_MESSAGE);
        }

        return y;
    }

    private static float processXAngle90(PDRectangle mediaBox, ImageAndResolution ires, SignatureImageParameters signatureImageParameters, BufferedImage visualImageSignature) {
        float x;

        SignatureImageParameters.VisualSignatureAlignmentVertical alignmentVertical = signatureImageParameters.getVisualSignatureAlignmentVertical();

        switch (alignmentVertical) {
            case TOP:
            case NONE:
                x = mediaBox.getWidth() - ires.toXPoint(visualImageSignature.getWidth()) - signatureImageParameters.getyAxis();
                break;
            case MIDDLE:
                x = (mediaBox.getWidth() - ires.toXPoint(visualImageSignature.getWidth())) / 2;
                break;
            case BOTTOM:
                x = signatureImageParameters.getyAxis();
                break;
            default:
                throw new IllegalStateException(SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical.name());
        }

        return x;
    }

    private static float processXAngle180(PDRectangle mediaBox, ImageAndResolution ires, SignatureImageParameters signatureImageParameters, BufferedImage visualImageSignature) {
        float x;

        SignatureImageParameters.VisualSignatureAlignmentHorizontal alignmentHorizontal = signatureImageParameters.getVisualSignatureAlignmentHorizontal();

        switch (alignmentHorizontal) {
            case LEFT:
            case NONE:
                x = mediaBox.getWidth() - ires.toXPoint(visualImageSignature.getWidth()) - signatureImageParameters.getxAxis();
                break;
            case CENTER:
                x = (mediaBox.getWidth() - ires.toXPoint(visualImageSignature.getWidth())) / 2;
                break;
            case RIGHT:
                x = signatureImageParameters.getxAxis();
                break;
            default:
                throw new IllegalStateException(SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal.name());
        }

        return x;
    }

    private static float processXAngle270(PDRectangle mediaBox, ImageAndResolution ires, SignatureImageParameters signatureImageParameters, BufferedImage visualImageSignature) {
        float x;

        SignatureImageParameters.VisualSignatureAlignmentVertical alignmentVertical = signatureImageParameters.getVisualSignatureAlignmentVertical();

        switch (alignmentVertical) {
            case TOP:
            case NONE:
                x = signatureImageParameters.getyAxis();
                break;
            case MIDDLE:
                x = (mediaBox.getWidth() - ires.toXPoint(visualImageSignature.getWidth())) / 2;
                break;
            case BOTTOM:
                x = mediaBox.getWidth() - ires.toXPoint(visualImageSignature.getWidth()) - signatureImageParameters.getyAxis();
                break;
            default:
                throw new IllegalStateException(SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical.name());
        }

        return x;
    }

    private static float processXAngle360(PDRectangle mediaBox, ImageAndResolution ires, SignatureImageParameters signatureImageParameters, BufferedImage visualImageSignature) {
        float x;

        SignatureImageParameters.VisualSignatureAlignmentHorizontal alignmentHorizontal = signatureImageParameters.getVisualSignatureAlignmentHorizontal();

        switch (alignmentHorizontal) {
            case LEFT:
            case NONE:
                x = signatureImageParameters.getxAxis();
                break;
            case CENTER:
                x = (mediaBox.getWidth() - ires.toXPoint(visualImageSignature.getWidth())) / 2;
                break;
            case RIGHT:
                x = mediaBox.getWidth() -ires.toXPoint(visualImageSignature.getWidth()) - signatureImageParameters.getxAxis();
                break;
            default:
                throw new IllegalStateException(SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal.name());
        }

        return x;
    }

    private static float processYAngle90(PDRectangle mediaBox, ImageAndResolution ires, SignatureImageParameters signatureImageParameters, BufferedImage visualImageSignature) {
        float y;

        SignatureImageParameters.VisualSignatureAlignmentHorizontal alignmentHorizontal = signatureImageParameters.getVisualSignatureAlignmentHorizontal();

        switch (alignmentHorizontal) {
            case LEFT:
            case NONE:
                y = signatureImageParameters.getxAxis();
                break;
            case CENTER:
                y = (mediaBox.getHeight() - ires.toXPoint(visualImageSignature.getHeight())) / 2;
                break;
            case RIGHT:
                y = mediaBox.getHeight() - ires.toYPoint(visualImageSignature.getHeight()) - signatureImageParameters.getxAxis();
                break;
            default:
                throw new IllegalStateException(SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal.name());
        }

        return y;
    }

    private static float processYAngle180(PDRectangle mediaBox, ImageAndResolution ires, SignatureImageParameters signatureImageParameters, BufferedImage visualImageSignature) {
        float y;

        SignatureImageParameters.VisualSignatureAlignmentVertical alignmentVertical = signatureImageParameters.getVisualSignatureAlignmentVertical();

        switch (alignmentVertical) {
            case TOP:
            case NONE:
                y = mediaBox.getHeight() - ires.toYPoint(visualImageSignature.getHeight()) - signatureImageParameters.getyAxis();
                break;
            case MIDDLE:
                y = (mediaBox.getHeight() - ires.toYPoint(visualImageSignature.getHeight())) / 2;
                break;
            case BOTTOM:
                y = signatureImageParameters.getyAxis();
                break;
            default:
                throw new IllegalStateException(SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical.name());
        }

        return y;
    }

    private static float processYAngle270(PDRectangle mediaBox, ImageAndResolution ires, SignatureImageParameters signatureImageParameters, BufferedImage visualImageSignature) {
        float y;

        SignatureImageParameters.VisualSignatureAlignmentHorizontal alignmentHorizontal = signatureImageParameters.getVisualSignatureAlignmentHorizontal();

        switch (alignmentHorizontal) {
            case LEFT:
            case NONE:
                y = mediaBox.getHeight() - ires.toYPoint(visualImageSignature.getHeight()) - signatureImageParameters.getxAxis();
                break;
            case CENTER:
                y = (mediaBox.getHeight() - ires.toXPoint(visualImageSignature.getHeight())) / 2;
                break;
            case RIGHT:
                y = signatureImageParameters.getxAxis();
                break;
            default:
                throw new IllegalStateException(SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal.name());
        }

        return y;
    }

    private static float processYAngle360(PDRectangle mediaBox, ImageAndResolution ires, SignatureImageParameters signatureImageParameters, BufferedImage visualImageSignature) {
        float y;

        SignatureImageParameters.VisualSignatureAlignmentVertical alignmentVertical = signatureImageParameters.getVisualSignatureAlignmentVertical();

        switch (alignmentVertical) {
            case TOP:
            case NONE:
                y = signatureImageParameters.getyAxis();
                break;
            case MIDDLE:
                y = (mediaBox.getHeight() - ires.toYPoint(visualImageSignature.getHeight())) / 2;
                break;
            case BOTTOM:
                y = mediaBox.getHeight() - ires.toYPoint(visualImageSignature.getHeight()) - signatureImageParameters.getyAxis();
                break;
            default:
                throw new IllegalStateException(SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical.name());
        }

        return y;
    }

}
