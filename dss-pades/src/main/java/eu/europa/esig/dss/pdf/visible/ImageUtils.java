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
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.utils.Utils;

/**
 * Static utilities that helps in creating ImageAndResolution
 * 
 * @author pakeyser
 */
public class ImageUtils {

	private static final Logger LOG = LoggerFactory.getLogger(ImageUtils.class);

	private static final int[] IMAGE_TRANSPARENT_TYPES;

	private static final int DEFAULT_DPI = 96;

	/**
	 * Defines a number of a first page in a document
	 */
	public static final int DEFAULT_FIRST_PAGE = 1;

	static {
		int[] imageAlphaTypes = new int[] { BufferedImage.TYPE_4BYTE_ABGR, BufferedImage.TYPE_4BYTE_ABGR_PRE,
				BufferedImage.TYPE_INT_ARGB, BufferedImage.TYPE_INT_ARGB_PRE };
		Arrays.sort(imageAlphaTypes);
		IMAGE_TRANSPARENT_TYPES = imageAlphaTypes;
	}

	private ImageUtils() {
	}

	/**
	 * Reads image's metadata in a secure way. If metadata is not accessible from
	 * {@code image}, returns values from {@code imageParameters}
	 * 
	 * @param imageParameters {@link SignatureImageParameters}
	 * @return {@link ImageAndResolution} metadata
	 * @throws IOException in case of image reading error
	 */
	public static ImageAndResolution secureReadMetadata(SignatureImageParameters imageParameters) throws IOException {
		ImageAndResolution imageAndResolution;
		try {
			imageAndResolution = ImageUtils.readDisplayMetadata(imageParameters.getImage());
		} catch (Exception e) {
			LOG.warn("Cannot access the image metadata : {}. Returns default info.", e.getMessage());
			imageAndResolution = new ImageAndResolution(imageParameters.getImage(), imageParameters.getDpi(),
					imageParameters.getDpi());
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
			return image.getMimeType().equals(expectedContentType);
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
	 * Returns image boundary box. Tries to retrieve explicitly set values in the
	 * parameters, in other case reads dimensions from the provided image
	 * 
	 * @param imageParameters {@link SignatureImageParameters}
	 * @return {@link AnnotationBox}
	 */
	public static AnnotationBox getImageBoundaryBox(SignatureImageParameters imageParameters) {
		SignatureFieldParameters fieldParameters = imageParameters.getFieldParameters();
		float width = fieldParameters.getWidth();
		float height = fieldParameters.getHeight();
		float scaleFactor = getScaleFactor(imageParameters.getZoom());
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
		return new AnnotationBox(0, 0, width * scaleFactor, height * scaleFactor);
	}

	/**
	 * Returns a coefficient applying to a signature field width/height calculation
	 * 
	 * @param zoom - zoom value to compute scale factor from
	 * @return {@code float} scale factor
	 */
	public static float getScaleFactor(int zoom) {
		return zoom / 100f;
	}

	/**
	 * Reads image from InputStream. Detects and converts CMYK images to RGB if
	 * needed
	 * 
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

	/**
	 * Checks if the two given images are equal
	 * 
	 * @param img1 {@link BufferedImage}
	 * @param img2 {@link BufferedImage}
	 * @return TRUE if the two images are equal, FALSE otherwise
	 */
	public static boolean imagesEqual(BufferedImage img1, BufferedImage img2) {
		if (imageDimensionsEqual(img1, img2)) {
			int diffAmount = drawSubtractionImage(img1, img2, null);
			return diffAmount == 0;
		}
		return false;
	}

	/**
	 * Checks if the dimensions of the provided images is equal
	 * 
	 * @param img1 {@link BufferedImage}
	 * @param img2 {@link BufferedImage}
	 * @return TRUE if the size dimensions of both images is equal, FALSE otherwise
	 */
	public static boolean imageDimensionsEqual(BufferedImage img1, BufferedImage img2) {
		if ((img1.getWidth() != img2.getWidth()) || (img1.getHeight() != img2.getHeight())) {
			LOG.warn("Screenshot comparison error! Images dimensions mismatch.");
			return false;
		}
		return true;
	}

	/**
	 * Draws the subtraction image and returns different pixels amount
	 * 
	 * @param img1   {@link BufferedImage} to compare
	 * @param img2   {@link BufferedImage} to compare
	 * @param outImg {@link BufferedImage} the output result (subtraction image)
	 * @return amount of different pixels between two images
	 */
	public static int drawSubtractionImage(BufferedImage img1, BufferedImage img2, BufferedImage outImg) {
		int diffAmount = 0;
		int diff; // Defines current pixel color difference
		int result; // Stores output pixel
		for (int i = 0; i < img1.getHeight() && i < img2.getHeight(); i++) {
			for (int j = 0; j < img1.getWidth() && j < img2.getWidth(); j++) {
				int rgb1 = img1.getRGB(j, i);
				int rgb2 = img2.getRGB(j, i);
				int r1 = (rgb1 >> 16) & 0xff;
				int g1 = (rgb1 >> 8) & 0xff;
				int b1 = (rgb1) & 0xff;
				int r2 = (rgb2 >> 16) & 0xff;
				int g2 = (rgb2 >> 8) & 0xff;
				int b2 = (rgb2) & 0xff;

				// Overwrite for a new pixel
				diff = Math.abs(r1 - r2);
				diff += Math.abs(g1 - g2);
				diff += Math.abs(b1 - b2);

				if (diff > 0) {
					diffAmount++;
				}

				if (outImg != null) {
					// Change - Ensure result is between 0 - 255
					diff /= 3;
					// Make the difference image gray scale
					// The RGB components are all the same
					result = (diff << 16) | (diff << 8) | diff;
					// Set result
					outImg.setRGB(j, i, result);
				}
			}
		}
		return diffAmount;
	}

	public static String IMAGE_PLACING_MODE = "fill";

	/**
	 * Adjusts the coordinates of an image box so that an image with the
	 * given dimensions may fit in it by being stretched, scaled or
	 * centered, according to the placing behaviour specified in
	 * {@code imageParameters}.
	 *
	 * @param imageParameters the signature image parameters
	 * @param imageWidth the width of the image to fit
	 * @param imageHeight the heigth of the image to fit
	 * @param xAxis the lower left X coordinate of the image box
	 * @param yAxis the lower left Y coordinate of the image box
	 * @param width the width of the image box
	 * @param height the height of the image box
	 * @return a new image box that respects the placing behaviour specified
	 * in {@code imageParameters}
	 */
	public static AnnotationBox adjustImageBox(SignatureImageParameters imageParameters,
		int imageWidth, int imageHeight, float xAxis, float yAxis, float width, float height) {
		switch (IMAGE_PLACING_MODE) {
			case "fill":
				return new AnnotationBox(xAxis, yAxis, xAxis + width, yAxis + height);
			case "scale and center":
				return scaleAndCenter(imageWidth, imageHeight, xAxis, yAxis, width, height);
			case "center":
				if (imageWidth > width || imageHeight > height) {
					return scaleAndCenter(imageWidth, imageHeight, xAxis, yAxis, width, height);
				} else {
					return center(imageWidth, imageHeight, xAxis, yAxis, width, height);
				}
			default:
				throw new DSSException("Image placing mode not supported");
		}
	}

	/**
	 * Scales and centers an image with the given dimensions into a given
	 * image box. The returned image box will occupy as much as possible of
	 * the original image box while maitaining the aspect ratio of the
	 * original image.
	 *
	 * @param imageWidth the width of the image to fit
	 * @param imageHeight the heigth of the image to fit
	 * @param xAxis the lower left X coordinate of the image box
	 * @param yAxis the lower left Y coordinate of the image box
	 * @param width the width of the image box
	 * @param height the height of the image box
	 * @return a new image box that is scaled and centered to fit the
	 * original image box
	 */
	public static AnnotationBox scaleAndCenter(int imageWidth, int imageHeight, float xAxis, float yAxis, float width, float height) {
		double imageRatio = imageWidth / (double) imageHeight;
		double boxRatio = width / (double) height;

		int scaledWidth, scaledHeight;
		if (imageRatio < boxRatio) {
			scaledHeight = (int) height;
			scaledWidth = (int) (height * imageRatio);
		} else {
			scaledWidth = (int) width;
			scaledHeight = (int) (width / imageRatio);
		}

		return center(scaledWidth, scaledHeight, xAxis, yAxis, width, height);
	}

	/**
	 * Centers an image with the given dimensions into a given image box.
	 * The returned image box will have the exact same dimensions as the
	 * original image while being centered in the original image
	 * box.<br><br>
	 * NOTE: This method does not validate dimensions thus, if the original
	 * image is larger than than the original image box, the resulting image
	 * box will have it's borders outside of the original image box.
	 *
	 * @param imageWidth the width of the image to fit
	 * @param imageHeight the heigth of the image to fit
	 * @param xAxis the lower left X coordinate of the image box
	 * @param yAxis the lower left Y coordinate of the image box
	 * @param width the width of the image box
	 * @param height the height of the image box
	 * @return a new image box that is centered to fit the original image
	 * box
	 */
	public static AnnotationBox center(int imageWidth, int imageHeight, float xAxis, float yAxis, float width, float height) {
		float centeredX = xAxis + (width - imageWidth) / 2f;
		float centeredY = yAxis + (height - imageHeight) / 2f;

		return new AnnotationBox(centeredX, centeredY, centeredX + imageWidth, centeredY + imageHeight);
	}

}
