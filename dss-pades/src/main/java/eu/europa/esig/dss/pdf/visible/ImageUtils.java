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
package eu.europa.esig.dss.pdf.visible;

import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.awt.image.Raster;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Iterator;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.ImageTypeSpecifier;
import javax.imageio.metadata.IIOMetadata;
import javax.imageio.stream.ImageInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.pades.DSSFont;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.utils.Utils;

/**
 * Static utilities that helps in creating ImageAndResolution
 * @author pakeyser
 */
public class ImageUtils {

	private static final Logger LOG = LoggerFactory.getLogger(ImageUtils.class);

	private static final int[] IMAGE_TRANSPARENT_TYPES;
	
	private static final int DEFAULT_DPI = 96;

	static {
		int[] imageAlphaTypes = new int[] { BufferedImage.TYPE_4BYTE_ABGR, BufferedImage.TYPE_4BYTE_ABGR_PRE, BufferedImage.TYPE_INT_ARGB,
				BufferedImage.TYPE_INT_ARGB_PRE };
		Arrays.sort(imageAlphaTypes);
		IMAGE_TRANSPARENT_TYPES = imageAlphaTypes;
	}
	
	private ImageUtils() {
	}

	/**
	 * This method returns the image size with the original parameters (the generation uses DPI)
	 * 
	 * @param imageParameters
	 *            the image parameters
	 * @return a Dimension object
	 * @throws IOException
	 */
	public static Dimension getOptimalSize(SignatureImageParameters imageParameters) throws IOException {

		Dimension dimension = getImageDimension(imageParameters);
		double width = dimension.getWidth();
		double height = dimension.getHeight();

		SignatureImageTextParameters textParamaters = imageParameters.getTextParameters();
		if ((textParamaters != null) && !textParamaters.getText().isEmpty()) {
			Dimension textDimension = getTextDimension(imageParameters);
			switch (textParamaters.getSignerTextPosition()) {
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

		float ration = CommonDrawerUtils.getRation(imageParameters.getDpi());
		return new Dimension(Math.round((int)width / ration), Math.round((int)height / ration));
	}
	
	/**
	 * Reads image's metadata in a secure way. If metadata is not accessible from {@code image}, 
	 * returns values from {@code imageParameters}
	 * 
	 * @param image {@link DSSDocument} image to read metadata from
	 * @param imageParameters {@link SignatureImageParameters}
	 * @return {@link ImageAndResolution} metadata
	 * @throws IOException in case of image reading error
	 */
	public static ImageAndResolution secureReadMetadata(DSSDocument image, SignatureImageParameters imageParameters) throws IOException {
		ImageAndResolution imageAndResolution;
		try {
			imageAndResolution = ImageUtils.readDisplayMetadata(imageParameters.getImage());
		} catch (Exception e) {
			LOG.warn("Cannot access the image metadata : {}. Returns default info.", e.getMessage());
			imageAndResolution = new ImageAndResolution(imageParameters.getImage(), imageParameters.getDpi(), imageParameters.getDpi());
		}
		return imageAndResolution;
	}

	/**
	 * Reads image's metadata
	 * 
	 * @param image {@link DSSDocument} image to read metadata from
	 * @return {@link ImageAndResolution} metadata
	 * @throws IOException in case of image reading error
	 */
	public static ImageAndResolution readDisplayMetadata(DSSDocument image) throws IOException {
		if (isImageWithContentType(image, MimeType.JPEG)) {
			return readAndDisplayMetadataJPEG(image);
		} else if (isImageWithContentType(image, MimeType.PNG)) {
			return readAndDisplayMetadataPNG(image);
		}
		throw new DSSException("Unsupported image type");
	}

	private static boolean isImageWithContentType(DSSDocument image, MimeType expectedContentType) {
		if (image.getMimeType() != null) {
			return expectedContentType == image.getMimeType();
		} else if (image.getName() != null) {
			String contentType = null;
			try {
				contentType = Files.probeContentType(Paths.get(image.getName()));
			} catch (IOException e) {
				LOG.warn("Unable to retrieve the content-type : {}", e.getMessage());
			} catch (Exception e) {
				throw new DSSException("An error occurred during an attempt to read the image's content type", e);
			}
			return Utils.areStringsEqual(expectedContentType.getMimeTypeString(), contentType);
		} else {
			throw new DSSException("Cannot read image metadata. MimeType or image name must be specified!");
		}
	}

	private static ImageAndResolution readAndDisplayMetadataJPEG(DSSDocument image) throws IOException {
		try (InputStream is = image.openStream(); ImageInputStream iis = ImageIO.createImageInputStream(is)) {

			ImageReader reader = getImageReader("jpeg");
			// attach source to the reader
			reader.setInput(iis, true);
			
			int hdpi = DEFAULT_DPI;
			int vdpi = DEFAULT_DPI;

			if (isSupportedColorSpace(reader)) {
				// read metadata of first image
				IIOMetadata metadata = reader.getImageMetadata(0);

				Element root = (Element) metadata.getAsTree("javax_imageio_jpeg_image_1.0");

				NodeList elements = root.getElementsByTagName("app0JFIF");

				Element e = (Element) elements.item(0);
				hdpi = Integer.parseInt(e.getAttribute("Xdensity"));
				vdpi = Integer.parseInt(e.getAttribute("Ydensity"));
			} else {
				LOG.warn("Cannot read metadata of the image with name [{}]. The color space is not supported. "
						+ "Using the default dpi with value [{}]", image.getName(), DEFAULT_DPI);
			}

			return new ImageAndResolution(image, hdpi, vdpi);
		}
	}

	private static ImageAndResolution readAndDisplayMetadataPNG(DSSDocument image) throws IOException {
		try (InputStream is = image.openStream(); ImageInputStream iis = ImageIO.createImageInputStream(is)) {

			ImageReader reader = getImageReader("png");
			// attach source to the reader
			reader.setInput(iis, true);
			
			int hdpi = DEFAULT_DPI;
			int vdpi = DEFAULT_DPI;

			if (isSupportedColorSpace(reader)) {
				// read metadata of first image
				IIOMetadata metadata = reader.getImageMetadata(0);

				double mm2inch = 25.4;

				Element node = (Element) metadata.getAsTree("javax_imageio_1.0");
				NodeList lst = node.getElementsByTagName("HorizontalPixelSize");
				if (lst != null && lst.getLength() == 1) {
					hdpi = (int) (mm2inch / Float.parseFloat(((Element) lst.item(0)).getAttribute("value")));
				} else {
					LOG.debug("Cannot get HorizontalPixelSize value. Using the default dpi [{}]", DEFAULT_DPI);
				}

				lst = node.getElementsByTagName("VerticalPixelSize");
				if (lst != null && lst.getLength() == 1) {
					vdpi = (int) (mm2inch / Float.parseFloat(((Element) lst.item(0)).getAttribute("value")));
				} else {
					LOG.debug("Cannot get HorizontalPixelSize value. Using the default dpi [{}]", DEFAULT_DPI);
				}
			} else {
				LOG.warn("Cannot read metadata of the image with name [{}]. The color space is not supported. "
						+ "Using the default dpi with value [{}]", image.getName(), DEFAULT_DPI);
			}

			return new ImageAndResolution(image, hdpi, vdpi);
		}
	}
	
	private static boolean isSupportedColorSpace(ImageReader reader) throws IOException {
		Iterator<ImageTypeSpecifier> imageTypes = reader.getImageTypes(0);
		// ImageReader detects only processable types
		return imageTypes.hasNext();
	}
	
	/**
	 * Returns Dimensions. Tries to retrieve explicetly set values in the parameters,
	 * in other case reads dimensions from the provided image
	 * @param imageParameters {@link SignatureImageParameters}
	 * @return {@link Dimension}
	 */
	public static Dimension getImageDimension(SignatureImageParameters imageParameters) {
		float width = imageParameters.getWidth();
		float height = imageParameters.getHeight();
		float scaleFactor = imageParameters.getScaleFactor();
		if (width == 0 && height == 0) {
			try {
				DSSDocument docImage = imageParameters.getImage();
				if (docImage != null) {
					try (InputStream is = docImage.openStream()) {
						BufferedImage bufferedImage = read(is);
						width = bufferedImage.getWidth();
						height = bufferedImage.getHeight();
					}
				}
			} catch (IOException e) {
				LOG.error("Cannot read the given image", e);
			}
		}
		Dimension dimension = new Dimension();
		dimension.setSize((int)width * scaleFactor, (int)height * scaleFactor);
		return dimension;
	}
	
	/**
	 * Reads image from InputStream. Detects and converts CMYK images to RGB if needed
	 * @param is {@link InputStream} to read the image from
	 * @return {@link BufferedImage}
	 * @throws IOException - in case of InputStream reading error
	 */
	public static BufferedImage read(InputStream is) throws IOException {
		try (ImageInputStream iis = ImageIO.createImageInputStream(is)) {
			ImageReader imageReader = getImageReader(iis);
			imageReader.setInput(iis, true, true);
			if (isSupportedColorSpace(imageReader)) {
				return imageReader.read(0, imageReader.getDefaultReadParam());
			}
			LOG.warn("The image format is not supported by the current ImageReader!");
			Raster raster = getRaster(imageReader);
			if (isCMYKType(raster)) {
				LOG.info("Converting from CMYK to RGB...");
				return convertCMYKToRGB(raster);
			}
			throw new DSSException("The color space of image is not supported!");
		}
	}
	
	private static Raster getRaster(ImageReader imageReader) throws IOException {
		return imageReader.readRaster(0, imageReader.getDefaultReadParam());
	}
	
	private static boolean isCMYKType(Raster raster) {
		return raster.getNumBands() == 4; // number of parameters for CMYK color scheme per pixel
	}
	
	private static BufferedImage convertCMYKToRGB(Raster raster) throws IOException {
		int width = raster.getWidth();
		int height = raster.getHeight();
		BufferedImage rgbImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
		int[] cmyk = new int[4];
		int r, g, b, p;
		for (int y = 0; y < height; y++) {
			for (int x = 0; x < width; x++) {
				cmyk = raster.getPixel(x, y, cmyk);
				r = ((cmyk[0]) * (cmyk[3])) / 255;
				g = ((cmyk[1]) * (cmyk[3])) / 255;
				b = ((cmyk[2]) * (cmyk[3])) / 255;
				p = (r << 16) | (g << 8) | b;
				rgbImage.setRGB(x, y, p);
			}
		}
		return rgbImage;
	}

	/**
	 * Computes {@link Dimension} of the text box to create
	 * @param imageParameters {@link SignatureImageParameters} to use
	 * @return {@link Dimension} of the text box
	 */
	private static Dimension getTextDimension(SignatureImageParameters imageParameters) {
		SignatureImageTextParameters textParameters = imageParameters.getTextParameters();
		DSSFont dssFont = textParameters.getFont();
		Font properFont = FontUtils.computeProperFont(dssFont.getJavaFont(), dssFont.getSize(), imageParameters.getDpi());
		return FontUtils.computeSize(properFont, textParameters.getText(), textParameters.getPadding());
	}

	public static BufferedImage rotate(BufferedImage image, double angle) {
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

	private static ImageReader getImageReader(String type) {
		Iterator<ImageReader> readers = ImageIO.getImageReadersByFormatName(type);
		ImageReader reader = getRasterReader(readers);
		if (reader == null) {
			throw new DSSException("No reader for '" + type + "' found");
		}
		return reader;
	}
	
	private static ImageReader getImageReader(ImageInputStream iis) {
		Iterator<ImageReader> readers = ImageIO.getImageReaders(iis);
		ImageReader reader = getRasterReader(readers);
		if (reader == null) {
			throw new DSSException("No reader for the image found");
		}
		return reader;
	}
	
	private static ImageReader getRasterReader(Iterator<ImageReader> readers) {
		ImageReader reader = null;
		// pick the first available ImageReader that reads raster
		while (readers.hasNext()) {
			reader = readers.next();
			if (reader.canReadRaster()) {
				break;
			}
		}
		return reader;
	}

	public static boolean isTransparent(BufferedImage bufferedImage) {
		int type = bufferedImage.getType();
		return Arrays.binarySearch(IMAGE_TRANSPARENT_TYPES, type) > -1;
	}

	public static int getImageType(final BufferedImage image) {
		int imageType = BufferedImage.TYPE_INT_RGB;
		if (ImageUtils.isTransparent(image)) {
			LOG.warn("Transparency detected and enabled (Be aware: not valid with PDF/A !)");
			imageType = BufferedImage.TYPE_INT_ARGB;
		}
		return imageType;
	}

}
