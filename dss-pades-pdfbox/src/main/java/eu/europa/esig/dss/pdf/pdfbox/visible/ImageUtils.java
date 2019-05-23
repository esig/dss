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
package eu.europa.esig.dss.pdf.pdfbox.visible;

import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Iterator;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.metadata.IIOMetadata;
import javax.imageio.stream.ImageInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.pades.DSSFont;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.visible.CommonDrawerUtils;
import eu.europa.esig.dss.pdf.visible.FontUtils;
import eu.europa.esig.dss.pdf.visible.ImageAndResolution;
import eu.europa.esig.dss.utils.Utils;

/**
 * Static utilities that helps in creating ImageAndResolution
 * @author pakeyser
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

	private static boolean isImageWithContentType(DSSDocument image, MimeType expectedContentType) {
		if (image.getMimeType() != null) {
			return expectedContentType == image.getMimeType();
		} else {
			String contentType = null;
			try {
				contentType = Files.probeContentType(Paths.get(image.getName()));
			} catch (IOException e) {
				LOG.warn("Unable to retrieve the content-type : {}", e.getMessage());
			} catch (Exception e) {
				throw new DSSException("An error occurred during an attempt to read the image's content type", e);
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

	/**
	 * Computes {@link Dimension} of the text box to create
	 * @param imageParameters {@link SignatureImageParameters} to use
	 * @return {@link Dimension} of the text box
	 */
	private static Dimension getTextDimension(SignatureImageParameters imageParameters) {
		SignatureImageTextParameters textParameters = imageParameters.getTextParameters();
		DSSFont dssFont = textParameters.getFont();
		Font properFont = FontUtils.computeProperFont(dssFont.getJavaFont(), dssFont.getSize(), imageParameters.getDpi());
		return FontUtils.computeSize(properFont, textParameters.getText(), textParameters.getMargin());
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
		if (!readers.hasNext()) {
			throw new DSSException("No reader for '" + type + "' found");
		}
		// pick the first available ImageReader
		return readers.next();
	}

	public static boolean isTransparent(BufferedImage bufferedImage) {
		int type = bufferedImage.getType();
		return Arrays.binarySearch(IMAGE_TRANSPARENT_TYPES, type) > -1;
	}

}
