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

import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pdf.pdfbox.visible.ImageRotationUtils;
import eu.europa.esig.dss.pdf.visible.ImageAndResolution;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;

/**
 * Builds {@code SignatureImageAndPosition}
 */
public final class SignatureImageAndPositionBuilder {

	private static final String NOT_SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE = "not supported vertical alignment: ";
	private static final String NOT_SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE = "not supported horizontal alignment: ";

	/**
	 * Builds the {@code SignatureImageAndPosition}
	 *
	 * @param signatureImageParameters {@link SignatureImageParameters}
	 * @param doc {@link PDDocument}
	 * @param ires {@link ImageAndResolution}
	 * @return {@link SignatureImageAndPosition}
	 * @throws IOException if an exception occurs
	 */
	public SignatureImageAndPosition build(final SignatureImageParameters signatureImageParameters,
			final PDDocument doc, final ImageAndResolution ires) throws IOException {
		try (InputStream is = ires.getInputStream()) {

			BufferedImage visualImageSignature = ImageUtils.read(is);

			PDPage pdPage = doc.getPages()
					.get(signatureImageParameters.getFieldParameters().getPage() - ImageUtils.DEFAULT_FIRST_PAGE);

			int rotate = ImageRotationUtils.getRotation(signatureImageParameters.getRotation(), pdPage);
			if (rotate != ImageRotationUtils.ANGLE_360) {
				visualImageSignature = ImageUtils.rotate(visualImageSignature, rotate);
			}
			boolean swapDimensions = ImageRotationUtils.isSwapOfDimensionsRequired(rotate);

			float width = processWidth(swapDimensions, ires, visualImageSignature, signatureImageParameters);
			float height = processHeight(swapDimensions, ires, visualImageSignature, signatureImageParameters);

			float x = processX(rotate, ires, width, pdPage, signatureImageParameters);
			float y = processY(rotate, ires, height, pdPage, signatureImageParameters);

			return new SignatureImageAndPosition(x, y, width, height, visualImageSignature);
		}
	}

	private float processX(int rotation, ImageAndResolution ires, float boxWidth, PDPage pdPage,
			SignatureImageParameters signatureImageParameters) {
		float x;

		PDRectangle pageBox = pdPage.getMediaBox();

		switch (rotation) {
		case ImageRotationUtils.ANGLE_90:
			x = processXAngle90(pageBox, signatureImageParameters, boxWidth);
			break;
		case ImageRotationUtils.ANGLE_180:
			x = processXAngle180(pageBox, signatureImageParameters, boxWidth);
			break;
		case ImageRotationUtils.ANGLE_270:
			x = processXAngle270(pageBox, signatureImageParameters, boxWidth);
			break;
		case ImageRotationUtils.ANGLE_360:
			x = processXAngle360(pageBox, signatureImageParameters, boxWidth);
			break;
		default:
			throw new IllegalStateException(ImageRotationUtils.SUPPORTED_ANGLES_ERROR_MESSAGE);
		}

		return x;
	}

	private float processY(int rotation, ImageAndResolution ires, float boxHeight, PDPage pdPage,
			SignatureImageParameters signatureImageParameters) {
		float y;

		PDRectangle pageBox = pdPage.getMediaBox();

		switch (rotation) {
		case ImageRotationUtils.ANGLE_90:
			y = processYAngle90(pageBox, signatureImageParameters, boxHeight);
			break;
		case ImageRotationUtils.ANGLE_180:
			y = processYAngle180(pageBox, signatureImageParameters, boxHeight);
			break;
		case ImageRotationUtils.ANGLE_270:
			y = processYAngle270(pageBox, signatureImageParameters, boxHeight);
			break;
		case ImageRotationUtils.ANGLE_360:
			y = processYAngle360(pageBox, signatureImageParameters, boxHeight);
			break;
		default:
			throw new IllegalStateException(ImageRotationUtils.SUPPORTED_ANGLES_ERROR_MESSAGE);
		}

		return y;
	}

	private float processWidth(boolean swapDimensions, ImageAndResolution ires, BufferedImage visualImageSignature,
			SignatureImageParameters signatureImageParameters) {
		SignatureFieldParameters fieldParameters = signatureImageParameters.getFieldParameters();
		float width = swapDimensions ? fieldParameters.getHeight() : fieldParameters.getWidth();
		if (width == 0) {
			width = visualImageSignature.getWidth();
			width = swapDimensions ? ires.toYPoint(width) : ires.toXPoint(width);
		}
		return zoom(width, signatureImageParameters.getZoom());
	}

	private float processHeight(boolean swapDimensions, ImageAndResolution ires, BufferedImage visualImageSignature,
			SignatureImageParameters signatureImageParameters) {
		SignatureFieldParameters fieldParameters = signatureImageParameters.getFieldParameters();
		float height = swapDimensions ? fieldParameters.getWidth() : fieldParameters.getHeight();
		if (height == 0) {
			height = visualImageSignature.getHeight();
			height = swapDimensions ? ires.toXPoint(height) : ires.toYPoint(height);
		}
		return zoom(height, signatureImageParameters.getZoom());
	}

	private float zoom(float originalFloat, int zoom) {
		return originalFloat * zoom / 100;
	}

	private float processXAngle90(PDRectangle mediaBox, SignatureImageParameters signatureImageParameters,
			float width) {
		float x;
		SignatureFieldParameters fieldParameters = signatureImageParameters.getFieldParameters();

		VisualSignatureAlignmentVertical alignmentVertical = signatureImageParameters
				.getVisualSignatureAlignmentVertical();
		switch (alignmentVertical) {
		case TOP:
		case NONE:
			x = mediaBox.getWidth() - width - fieldParameters.getOriginY();
			break;
		case MIDDLE:
			x = (mediaBox.getWidth() - width) / 2;
			break;
		case BOTTOM:
			x = fieldParameters.getOriginY();
			break;
		default:
			throw new IllegalStateException(NOT_SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical.name());
		}

		return x;
	}

	private float processXAngle180(PDRectangle mediaBox, SignatureImageParameters signatureImageParameters,
			float width) {
		float x;
		SignatureFieldParameters fieldParameters = signatureImageParameters.getFieldParameters();

		VisualSignatureAlignmentHorizontal alignmentHorizontal = signatureImageParameters
				.getVisualSignatureAlignmentHorizontal();
		switch (alignmentHorizontal) {
		case LEFT:
		case NONE:
			x = mediaBox.getWidth() - width - fieldParameters.getOriginX();
			break;
		case CENTER:
			x = (mediaBox.getWidth() - width) / 2;
			break;
		case RIGHT:
			x = fieldParameters.getOriginX();
			break;
		default:
			throw new IllegalStateException(
					NOT_SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal.name());
		}

		return x;
	}

	private float processXAngle270(PDRectangle mediaBox, SignatureImageParameters signatureImageParameters,
			float width) {
		float x;
		SignatureFieldParameters fieldParameters = signatureImageParameters.getFieldParameters();

		VisualSignatureAlignmentVertical alignmentVertical = signatureImageParameters
				.getVisualSignatureAlignmentVertical();
		switch (alignmentVertical) {
		case TOP:
		case NONE:
			x = fieldParameters.getOriginY();
			break;
		case MIDDLE:
			x = (mediaBox.getWidth() - width) / 2;
			break;
		case BOTTOM:
			x = mediaBox.getWidth() - width - fieldParameters.getOriginY();
			break;
		default:
			throw new IllegalStateException(NOT_SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical.name());
		}

		return x;
	}

	private float processXAngle360(PDRectangle mediaBox, SignatureImageParameters signatureImageParameters,
			float width) {
		float x;
		SignatureFieldParameters fieldParameters = signatureImageParameters.getFieldParameters();

		VisualSignatureAlignmentHorizontal alignmentHorizontal = signatureImageParameters
				.getVisualSignatureAlignmentHorizontal();
		switch (alignmentHorizontal) {
		case LEFT:
		case NONE:
			x = fieldParameters.getOriginX();
			break;
		case CENTER:
			x = (mediaBox.getWidth() - width) / 2;
			break;
		case RIGHT:
			x = mediaBox.getWidth() - width - fieldParameters.getOriginX();
			break;
		default:
			throw new IllegalStateException(
					NOT_SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal.name());
		}

		return x;
	}

	private float processYAngle90(PDRectangle mediaBox, SignatureImageParameters signatureImageParameters,
			float height) {
		float y;
		SignatureFieldParameters fieldParameters = signatureImageParameters.getFieldParameters();

		VisualSignatureAlignmentHorizontal alignmentHorizontal = signatureImageParameters
				.getVisualSignatureAlignmentHorizontal();
		switch (alignmentHorizontal) {
		case LEFT:
		case NONE:
			y = fieldParameters.getOriginX();
			break;
		case CENTER:
			y = (mediaBox.getHeight() - height) / 2;
			break;
		case RIGHT:
			y = mediaBox.getHeight() - height - fieldParameters.getOriginX();
			break;
		default:
			throw new IllegalStateException(
					NOT_SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal.name());
		}

		return y;
	}

	private float processYAngle180(PDRectangle mediaBox, SignatureImageParameters signatureImageParameters,
			float height) {
		float y;
		SignatureFieldParameters fieldParameters = signatureImageParameters.getFieldParameters();

		VisualSignatureAlignmentVertical alignmentVertical = signatureImageParameters
				.getVisualSignatureAlignmentVertical();
		switch (alignmentVertical) {
		case TOP:
		case NONE:
			y = mediaBox.getHeight() - height - fieldParameters.getOriginY();
			break;
		case MIDDLE:
			y = (mediaBox.getHeight() - height) / 2;
			break;
		case BOTTOM:
			y = fieldParameters.getOriginY();
			break;
		default:
			throw new IllegalStateException(NOT_SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical.name());
		}

		return y;
	}

	private float processYAngle270(PDRectangle mediaBox, SignatureImageParameters signatureImageParameters,
			float height) {
		float y;
		SignatureFieldParameters fieldParameters = signatureImageParameters.getFieldParameters();

		VisualSignatureAlignmentHorizontal alignmentHorizontal = signatureImageParameters
				.getVisualSignatureAlignmentHorizontal();
		switch (alignmentHorizontal) {
		case LEFT:
		case NONE:
			y = mediaBox.getHeight() - height - fieldParameters.getOriginX();
			break;
		case CENTER:
			y = (mediaBox.getHeight() - height) / 2;
			break;
		case RIGHT:
			y = fieldParameters.getOriginX();
			break;
		default:
			throw new IllegalStateException(
					NOT_SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal.name());
		}

		return y;
	}

	private float processYAngle360(PDRectangle mediaBox, SignatureImageParameters signatureImageParameters,
			float height) {
		float y;
		SignatureFieldParameters fieldParameters = signatureImageParameters.getFieldParameters();

		VisualSignatureAlignmentVertical alignmentVertical = signatureImageParameters
				.getVisualSignatureAlignmentVertical();
		switch (alignmentVertical) {
		case TOP:
		case NONE:
			y = fieldParameters.getOriginY();
			break;
		case MIDDLE:
			y = (mediaBox.getHeight() - height) / 2;
			break;
		case BOTTOM:
			y = mediaBox.getHeight() - height - fieldParameters.getOriginY();
			break;
		default:
			throw new IllegalStateException(NOT_SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical.name());
		}

		return y;
	}

}
