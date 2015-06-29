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

import java.awt.Dimension;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageTypeSpecifier;
import javax.imageio.ImageWriter;
import javax.imageio.metadata.IIOInvalidTreeException;
import javax.imageio.metadata.IIOMetadata;
import javax.imageio.plugins.jpeg.JPEGImageWriteParam;
import javax.imageio.stream.ImageOutputStream;

import org.apache.commons.lang.StringUtils;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;

public final class ImageFactory {

	private static final int DPI = 300;

	private ImageFactory(){
	}

	/**
	 * This method returns the image size with the original parameters (the generation uses DPI)
	 * @param imageParameters the image parameters
	 * @return a Dimension object
	 * @throws IOException
	 */
	public static Dimension getOptimalSize(SignatureImageParameters imageParameters) throws IOException {
		int width = 0;
		int height = 0;

		if (imageParameters.getImage() != null) {
			BufferedImage image = ImageIO.read(imageParameters.getImage());
			width = image.getWidth();
			height = image.getHeight();
		}

		SignatureImageTextParameters textParamaters = imageParameters.getTextParameters();
		if ((textParamaters != null) && StringUtils.isNotEmpty(textParamaters.getText())) {
			Dimension textDimension = ImageTextWriter.computeSize(textParamaters.getFont(), textParamaters.getText());
			switch (textParamaters.getSignerNamePosition()) {
				case LEFT:
				case RIGHT:
					width += textDimension.width;
					height = Math.max(height, textDimension.height);
					break;
				case TOP:
				case BOTTOM:
					width = Math.max(width, textDimension.width);
					height += textDimension.height;
					break;
				default:
					break;
			}

		}

		return new Dimension(width, height);
	}

	public static InputStream create(final SignatureImageParameters imageParameters) throws IOException {

		SignatureImageTextParameters textParamaters = imageParameters.getTextParameters();

		if ((textParamaters != null) && StringUtils.isNotEmpty(textParamaters.getText())) {

			BufferedImage buffImg = ImageTextWriter.createTextImage(textParamaters.getText(), textParamaters.getFont(), textParamaters.getTextColor(),
					textParamaters.getBackgroundColor(), DPI);

			if (imageParameters.getImage() != null) {
				switch (textParamaters.getSignerNamePosition()) {
					case LEFT:
						buffImg = ImagesMerger.mergeOnRight(ImageIO.read(imageParameters.getImage()), buffImg, textParamaters.getBackgroundColor());
						break;
					case RIGHT:
						buffImg = ImagesMerger.mergeOnRight(buffImg, ImageIO.read(imageParameters.getImage()), textParamaters.getBackgroundColor());
						break;
					case TOP:
						buffImg = ImagesMerger.mergeOnTop(ImageIO.read(imageParameters.getImage()), buffImg, textParamaters.getBackgroundColor());
						break;
					case BOTTOM:
						buffImg = ImagesMerger.mergeOnTop(buffImg, ImageIO.read(imageParameters.getImage()), textParamaters.getBackgroundColor());
						break;
					default:
						break;
				}
			}
			return convertToInputStream(buffImg, DPI);
		} else {
			return new FileInputStream(imageParameters.getImage());
		}
	}

	private static InputStream convertToInputStream(BufferedImage buffImage, int dpi) throws IOException {
		Iterator<ImageWriter> it = ImageIO.getImageWritersByFormatName("jpeg");
		if (!it.hasNext()) {
			throw new DSSException("No writer for JPEG found");
		}
		ImageWriter writer = it.next();

		JPEGImageWriteParam jpegParams = (JPEGImageWriteParam) writer.getDefaultWriteParam();
		jpegParams.setCompressionMode(JPEGImageWriteParam.MODE_EXPLICIT);
		jpegParams.setCompressionQuality(1);

		ImageTypeSpecifier typeSpecifier = ImageTypeSpecifier.createFromBufferedImageType(BufferedImage.TYPE_INT_RGB);
		IIOMetadata metadata = writer.getDefaultImageMetadata(typeSpecifier, jpegParams);

		initDpi(metadata, dpi);

		ByteArrayOutputStream os = new ByteArrayOutputStream();
		ImageOutputStream imageOs = ImageIO.createImageOutputStream(os);
		writer.setOutput(imageOs);
		writer.write(metadata, new IIOImage(buffImage, null, metadata), jpegParams);

		InputStream is = new ByteArrayInputStream(os.toByteArray());
		return is;
	}

	private static void initDpi(IIOMetadata metadata, int dpi) throws IIOInvalidTreeException {
		Element tree = (Element) metadata.getAsTree("javax_imageio_jpeg_image_1.0");
		Element jfif = (Element) tree.getElementsByTagName("app0JFIF").item(0);
		jfif.setAttribute("Xdensity", Integer.toString(dpi));
		jfif.setAttribute("Ydensity", Integer.toString(dpi));
		jfif.setAttribute("resUnits", "1"); // density is dots per inch
		metadata.setFromTree("javax_imageio_jpeg_image_1.0", tree);
	}

}
