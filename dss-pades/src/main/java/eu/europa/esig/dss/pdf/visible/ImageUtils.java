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
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Iterator;

import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.ImageTypeSpecifier;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.metadata.IIOInvalidTreeException;
import javax.imageio.metadata.IIOMetadata;
import javax.imageio.metadata.IIOMetadataNode;
import javax.imageio.plugins.jpeg.JPEGImageWriteParam;
import javax.imageio.stream.ImageInputStream;
import javax.imageio.stream.ImageOutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.utils.Utils;

/**
 * Static utilities that helps in creating ImageAndResolution
 * 
 * @author pakeyser
 *
 */
public class ImageUtils {

	private static final Logger LOG = LoggerFactory.getLogger(ImageUtils.class);

	private static final int[] IMAGE_TRANSPARENT_TYPES;

	static {
		int[] imageAlphaTypes = new int[] { BufferedImage.TYPE_4BYTE_ABGR, BufferedImage.TYPE_4BYTE_ABGR_PRE, BufferedImage.TYPE_INT_ARGB,
				BufferedImage.TYPE_INT_ARGB_PRE };
		Arrays.sort(imageAlphaTypes);
		IMAGE_TRANSPARENT_TYPES = imageAlphaTypes;
	}

	private ImageUtils() {
	}

	public static ImageAndResolution create(final SignatureImageParameters imageParameters) throws IOException {
		SignatureImageTextParameters textParamaters = imageParameters.getTextParameters();

		DSSDocument image = imageParameters.getImage();
		if ((textParamaters != null) && Utils.isStringNotEmpty(textParamaters.getText())) {
			BufferedImage buffImg = ImageTextWriter.createTextImage(textParamaters.getText(), textParamaters.getJavaFont(), textParamaters.getSize(), 
					textParamaters.getTextColor(), textParamaters.getBackgroundColor(), textParamaters.getMargin(), imageParameters.getDpi(), 
					textParamaters.getSignerTextHorizontalAlignment());

			if (image != null) {
				// need to scale image due to usage default page 300 dpi instead of native image parameters
				BufferedImage scaledImage = getDpiScaledImage(image);
				if (scaledImage != null) {
					float zoomFactor = imageParameters.getScaleFactor();
					scaledImage = zoomImage(scaledImage, zoomFactor, zoomFactor);
					switch (textParamaters.getSignerNamePosition()) {
						case LEFT:
							buffImg = ImagesMerger.mergeOnRight(buffImg, scaledImage, textParamaters.getBackgroundColor(),
									imageParameters.getSignerTextImageVerticalAlignment());
							break;
						case RIGHT:
							buffImg = ImagesMerger.mergeOnRight(scaledImage, buffImg, textParamaters.getBackgroundColor(),
									imageParameters.getSignerTextImageVerticalAlignment());
							break;
						case TOP:
							buffImg = ImagesMerger.mergeOnTop(scaledImage, buffImg, textParamaters.getBackgroundColor());
							break;
						case BOTTOM:
							buffImg = ImagesMerger.mergeOnTop(buffImg, scaledImage, textParamaters.getBackgroundColor());
							break;
						default:
							break;
					}
				}
			}
			return convertToInputStream(buffImg, CommonDrawerUtils.getDpi(imageParameters.getDpi()));
		}

		// Image only
		return readDisplayMetadata(image);
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

		float ration = CommonDrawerUtils.getRation(imageParameters.getDpi());
		return new Dimension(Math.round((int)width / ration), Math.round((int)height / ration));
	}

	public static ImageAndResolution readDisplayMetadata(DSSDocument image) throws IOException {
		if (isImageWithContentType(image, MimeType.JPEG)) {
			return readAndDisplayMetadataJPEG(image);
		} else if (isImageWithContentType(image, MimeType.PNG)) {
			return readAndDisplayMetadataPNG(image);
		}
		throw new DSSException("Unsupported image type");
	}
	
	/**
	 * Returns a scaled {@link BufferedImage} based on its dpi parameters relatively to page dpi
	 * @param image {@link BufferedImage} to scale
	 * @return scaled {@link BufferedImage}
	 * @throws IOException in case of error
	 */
	private static BufferedImage getDpiScaledImage(DSSDocument image) throws IOException {
		ImageAndResolution imageAndResolution = readDisplayMetadata(image);
		try (InputStream is = image.openStream()) {
			if (is != null) {
				BufferedImage original = ImageIO.read(is);
				float xScaleFactor = CommonDrawerUtils.getScaleFactor(imageAndResolution.getxDpi());
				float yScaleFactor = CommonDrawerUtils.getScaleFactor(imageAndResolution.getyDpi());
				return zoomImage(original, xScaleFactor, yScaleFactor);
			}
			return null;
		}
	}
	
	/**
	 * Scale the original image according to given X and Y based scale factors
	 * @param original {@link BufferedImage} to zoom
	 * @param xScaleFactor zoom value by X axis
	 * @param yScaleFactor zoom value by Y axis
	 * @return resized original {@link BufferedImage)
	 * @throws IOException in case of error
	 */
	private static BufferedImage zoomImage(BufferedImage original, float xScaleFactor, float yScaleFactor) throws IOException {
		int newWidth = (int) (original.getWidth() * xScaleFactor);
		int newHeight = (int) (original.getHeight() * yScaleFactor);
		
		BufferedImage resized = new BufferedImage(newWidth, newHeight, original.getType());
		Graphics2D gr = resized.createGraphics();
		gr.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
		gr.drawImage(original, 0, 0, newWidth, newHeight, 0, 0, original.getWidth(), original.getHeight(), null);
		gr.dispose();
		
		return resized;
	}

	private static boolean isImageWithContentType(DSSDocument image, MimeType expectedContentType) {
		if (image.getMimeType() != null) {
			return expectedContentType == image.getMimeType();
		} else {
			String contentType = null;
			try {
				contentType = Files.probeContentType(Paths.get(image.getName()));
			} catch (IOException e) {
				LOG.warn("Unable to retrieve the content-type : {}", e.getMessage());
			}
			return Utils.areStringsEqual(expectedContentType.getMimeTypeString(), contentType);
		}
	}

	private static ImageAndResolution readAndDisplayMetadataJPEG(DSSDocument image) throws IOException {
		try (InputStream is = image.openStream(); ImageInputStream iis = ImageIO.createImageInputStream(is)) {

			ImageReader reader = getImageReader("jpeg");
			// attach source to the reader
			reader.setInput(iis, true);

			// read metadata of first image
			IIOMetadata metadata = reader.getImageMetadata(0);

			Element root = (Element) metadata.getAsTree("javax_imageio_jpeg_image_1.0");

			NodeList elements = root.getElementsByTagName("app0JFIF");

			Element e = (Element) elements.item(0);
			int x = Integer.parseInt(e.getAttribute("Xdensity"));
			int y = Integer.parseInt(e.getAttribute("Ydensity"));

			return new ImageAndResolution(image, x, y);
		}
	}

	private static ImageAndResolution readAndDisplayMetadataPNG(DSSDocument image) throws IOException {
		try (InputStream is = image.openStream(); ImageInputStream iis = ImageIO.createImageInputStream(is)) {

			ImageReader reader = getImageReader("png");
			// attach source to the reader
			reader.setInput(iis, true);

			// read metadata of first image
			IIOMetadata metadata = reader.getImageMetadata(0);

			int hdpi = 96;
			int vdpi = 96;
			double mm2inch = 25.4;

			Element node = (Element) metadata.getAsTree("javax_imageio_1.0");
			NodeList lst = node.getElementsByTagName("HorizontalPixelSize");
			if (lst != null && lst.getLength() == 1) {
				hdpi = (int) (mm2inch / Float.parseFloat(((Element) lst.item(0)).getAttribute("value")));
			}

			lst = node.getElementsByTagName("VerticalPixelSize");
			if (lst != null && lst.getLength() == 1) {
				vdpi = (int) (mm2inch / Float.parseFloat(((Element) lst.item(0)).getAttribute("value")));
			}

			return new ImageAndResolution(image, hdpi, vdpi);
		}
	}
	
	public static Dimension getImageDimension(SignatureImageParameters imageParameters) {
		float width = 0;
		float height = 0;
		float scaleFactor = imageParameters.getScaleFactor();
		try {
			DSSDocument docImage = imageParameters.getImage();
			if (docImage != null) {
				try (InputStream is = docImage.openStream()) {
					BufferedImage image = ImageIO.read(is);
					width = image.getWidth() * scaleFactor;
					height = image.getHeight() * scaleFactor;
				}
		}
		} catch (IOException e) {
			LOG.error("Cannot read the given image", e);
		}
		Dimension dimension = new Dimension();
		dimension.setSize(width, height);
		return dimension;
	}

	private static Dimension getTextDimension(SignatureImageParameters imageParameters) throws IOException {
		SignatureImageTextParameters textParameters = imageParameters.getTextParameters();
		Font properFont = ImageTextWriter.computeProperFont(textParameters.getJavaFont(), textParameters.getSize(), imageParameters.getDpi());
		return ImageTextWriter.computeSize(properFont, textParameters.getText(), textParameters.getMargin());
	}

	private static ImageAndResolution convertToInputStream(BufferedImage buffImage, int dpi) throws IOException {
		if (isTransparent(buffImage)) {
			return convertToInputStreamPNG(buffImage, dpi);
		} else {
			return convertToInputStreamJPG(buffImage, dpi);
		}
	}

	private static ImageAndResolution convertToInputStreamJPG(BufferedImage buffImage, int dpi) throws IOException {
		ImageWriter writer = getImageWriter("jpeg");

		JPEGImageWriteParam jpegParams = (JPEGImageWriteParam) writer.getDefaultWriteParam();
		jpegParams.setCompressionMode(JPEGImageWriteParam.MODE_EXPLICIT);
		jpegParams.setCompressionQuality(1);

		ImageTypeSpecifier typeSpecifier = ImageTypeSpecifier.createFromBufferedImageType(BufferedImage.TYPE_INT_RGB);
		IIOMetadata metadata = writer.getDefaultImageMetadata(typeSpecifier, jpegParams);

		initDpiJPG(metadata, dpi);

		return getImageAndResolution(buffImage, dpi, writer, jpegParams, metadata);
	}

	private static void initDpiJPG(IIOMetadata metadata, int dpi) throws IIOInvalidTreeException {
		Element tree = (Element) metadata.getAsTree("javax_imageio_jpeg_image_1.0");
		Element jfif = (Element) tree.getElementsByTagName("app0JFIF").item(0);
		jfif.setAttribute("Xdensity", Integer.toString(dpi));
		jfif.setAttribute("Ydensity", Integer.toString(dpi));
		jfif.setAttribute("resUnits", "1"); // density is dots per inch
		metadata.setFromTree("javax_imageio_jpeg_image_1.0", tree);
	}

	private static ImageAndResolution convertToInputStreamPNG(BufferedImage buffImage, int dpi) throws IOException {
		ImageWriter writer = getImageWriter("png");

		ImageWriteParam imageWriterParams = writer.getDefaultWriteParam();

		ImageTypeSpecifier typeSpecifier = ImageTypeSpecifier.createFromBufferedImageType(BufferedImage.TYPE_INT_ARGB);
		IIOMetadata metadata = writer.getDefaultImageMetadata(typeSpecifier, imageWriterParams);

		initDpiPNG(metadata, dpi);

		return getImageAndResolution(buffImage, dpi, writer, imageWriterParams, metadata);
	}

	private static ImageAndResolution getImageAndResolution(BufferedImage buffImage, int dpi, ImageWriter writer, ImageWriteParam imageWriterParams,
			IIOMetadata metadata) throws IOException {
		try (ByteArrayOutputStream os = new ByteArrayOutputStream(); ImageOutputStream imageOs = ImageIO.createImageOutputStream(os)) {
			writer.setOutput(imageOs);
			writer.write(metadata, new IIOImage(buffImage, null, metadata), imageWriterParams);
			return new ImageAndResolution(new InMemoryDocument(os.toByteArray()), dpi, dpi);
		}
	}

	private static void initDpiPNG(IIOMetadata metadata, int dpi) throws IIOInvalidTreeException {

		// for PNG, it's dots per millimeter
		double dotsPerMilli = 1.0 * dpi / 25.4;

		IIOMetadataNode horiz = new IIOMetadataNode("HorizontalPixelSize");
		horiz.setAttribute("value", Double.toString(dotsPerMilli));

		IIOMetadataNode vert = new IIOMetadataNode("VerticalPixelSize");
		vert.setAttribute("value", Double.toString(dotsPerMilli));

		IIOMetadataNode dim = new IIOMetadataNode("Dimension");
		dim.appendChild(horiz);
		dim.appendChild(vert);

		IIOMetadataNode root = new IIOMetadataNode("javax_imageio_1.0");
		root.appendChild(dim);

		metadata.mergeTree("javax_imageio_1.0", root);
	}

	public static boolean isTransparent(BufferedImage bufferedImage) {
		int type = bufferedImage.getType();

		return Arrays.binarySearch(IMAGE_TRANSPARENT_TYPES, type) > -1;
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

	private static ImageWriter getImageWriter(String type) {
		Iterator<ImageWriter> writers = ImageIO.getImageWritersByFormatName(type);
		if (!writers.hasNext()) {
			throw new DSSException("No writer for '" + type + "' found");
		}
		return writers.next();
	}

	private static ImageReader getImageReader(String type) {
		Iterator<ImageReader> readers = ImageIO.getImageReadersByFormatName(type);
		if (!readers.hasNext()) {
			throw new DSSException("No reader for '" + type + "' found");
		}
		// pick the first available ImageReader
		return readers.next();
	}

}
