package eu.europa.esig.dss.pdf.pdfbox.visible.defaultdrawer;

import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageTypeSpecifier;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.metadata.IIOInvalidTreeException;
import javax.imageio.metadata.IIOMetadata;
import javax.imageio.metadata.IIOMetadataNode;
import javax.imageio.plugins.jpeg.JPEGImageWriteParam;
import javax.imageio.stream.ImageOutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.pdfbox.visible.ImageUtils;
import eu.europa.esig.dss.pdf.visible.CommonDrawerUtils;
import eu.europa.esig.dss.pdf.visible.ImageAndResolution;
import eu.europa.esig.dss.utils.Utils;

public class DefaultDrawerImageUtils {

	private static final Logger LOG = LoggerFactory.getLogger(DefaultDrawerImageUtils.class);

	private DefaultDrawerImageUtils() {
	}

	public static ImageAndResolution create(final SignatureImageParameters imageParameters) throws IOException {
		SignatureImageTextParameters textParamaters = imageParameters.getTextParameters();

		DSSDocument image = imageParameters.getImage();
		if ((textParamaters != null) && Utils.isStringNotEmpty(textParamaters.getText())) {
			BufferedImage buffImg = ImageTextWriter.createTextImage(imageParameters);

			if (image != null) {
				// need to scale image due to usage default page 300 dpi instead of native image parameters
				BufferedImage scaledImage = getDpiScaledImage(image);
				if (scaledImage != null) {
					float zoomFactor = imageParameters.getScaleFactor();
					scaledImage = zoomImage(scaledImage, zoomFactor, zoomFactor);
					switch (textParamaters.getSignerNamePosition()) {
						case LEFT:
							buffImg = ImageMerger.mergeOnRight(buffImg, scaledImage, imageParameters.getBackgroundColor(),
									imageParameters.getSignerTextImageVerticalAlignment());
							break;
						case RIGHT:
							buffImg = ImageMerger.mergeOnRight(scaledImage, buffImg, imageParameters.getBackgroundColor(),
									imageParameters.getSignerTextImageVerticalAlignment());
							break;
						case TOP:
							buffImg = ImageMerger.mergeOnTop(scaledImage, buffImg, imageParameters.getBackgroundColor());
							break;
						case BOTTOM:
							buffImg = ImageMerger.mergeOnTop(buffImg, scaledImage, imageParameters.getBackgroundColor());
							break;
						default:
							break;
					}
				}
			}
			return convertToInputStream(buffImg, CommonDrawerUtils.getDpi(imageParameters.getDpi()));
		}

		// Image only
		return ImageUtils.readDisplayMetadata(image);
	}
	
	/**
	 * Returns a scaled {@link BufferedImage} based on its dpi parameters relatively to page dpi
	 * @param image {@link BufferedImage} to scale
	 * @return scaled {@link BufferedImage}
	 * @throws IOException in case of error
	 */
	private static BufferedImage getDpiScaledImage(DSSDocument image) throws IOException {
		try (InputStream is = image.openStream()) {
			if (is != null) {
				BufferedImage original = ImageIO.read(is);
				try {
					ImageAndResolution imageAndResolution = ImageUtils.readDisplayMetadata(image);
					float xScaleFactor = CommonDrawerUtils.getScaleFactor(imageAndResolution.getxDpi());
					float yScaleFactor = CommonDrawerUtils.getScaleFactor(imageAndResolution.getyDpi());
					return zoomImage(original, xScaleFactor, yScaleFactor);
				} catch (DSSException e) {
					LOG.warn("Cannot zoom image. Return the original : {}", e.getMessage());
					return original;
				}
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
	private static BufferedImage zoomImage(BufferedImage original, float xScaleFactor, float yScaleFactor) {
		int newWidth = (int) (original.getWidth() * xScaleFactor);
		int newHeight = (int) (original.getHeight() * yScaleFactor);
		
		BufferedImage resized = new BufferedImage(newWidth, newHeight, original.getType());
		Graphics2D gr = resized.createGraphics();
		gr.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
		gr.drawImage(original, 0, 0, newWidth, newHeight, 0, 0, original.getWidth(), original.getHeight(), null);
		gr.dispose();
		
		return resized;
	}

	private static ImageAndResolution convertToInputStream(BufferedImage buffImage, int dpi) throws IOException {
		if (ImageUtils.isTransparent(buffImage)) {
			return convertToInputStreamPNG(buffImage, dpi);
		} else {
			return convertToInputStreamJPG(buffImage, dpi);
		}
	}	private static ImageAndResolution convertToInputStreamJPG(BufferedImage buffImage, int dpi) throws IOException {
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

	private static ImageWriter getImageWriter(String type) {
		Iterator<ImageWriter> writers = ImageIO.getImageWritersByFormatName(type);
		if (!writers.hasNext()) {
			throw new DSSException("No writer for '" + type + "' found");
		}
		return writers.next();
	}

}
