package eu.europa.esig.dss.pdf.pdfbox.visible.defaultdrawer;

import java.awt.AlphaComposite;
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

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters.SignerPosition;
import eu.europa.esig.dss.pdf.visible.CommonDrawerUtils;
import eu.europa.esig.dss.pdf.visible.ImageAndResolution;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.utils.Utils;

public class DefaultDrawerImageUtils {

	private static final Logger LOG = LoggerFactory.getLogger(DefaultDrawerImageUtils.class);

	private DefaultDrawerImageUtils() {
	}

	public static ImageAndResolution create(final SignatureImageParameters imageParameters) throws IOException {
		SignatureImageTextParameters textParamaters = imageParameters.getTextParameters();
		DSSDocument image = imageParameters.getImage();
		
		if ((textParamaters != null) && Utils.isStringNotEmpty(textParamaters.getText())) {
			BufferedImage scaledImage = null;
			if (image != null) {
				scaledImage = getDpiScaledImage(image, imageParameters);
			}
			
			BufferedImage buffImg = ImageTextWriter.createTextImage(imageParameters);

			if (scaledImage == null && buffImg != null) {
				// reserve empty space if only text must be drawed
				scaledImage = createEmptyImage(imageParameters, buffImg.getWidth(), buffImg.getHeight());
			}
			
			if (scaledImage != null) {
				float zoomFactor = imageParameters.getScaleFactor();
				if (zoomFactor != 1) {
					scaledImage = zoomImage(scaledImage, zoomFactor, zoomFactor);
				}
				SignerPosition signerNamePosition = textParamaters.getSignerNamePosition();
				switch (signerNamePosition) {
					case LEFT:
						scaledImage = writeImageToSignatureField(scaledImage, buffImg, imageParameters, false);
						buffImg = ImageMerger.mergeOnRight(buffImg, scaledImage, imageParameters.getBackgroundColor(), imageParameters.getSignerTextImageVerticalAlignment());
						break;
					case RIGHT:
						scaledImage = writeImageToSignatureField(scaledImage, buffImg, imageParameters, false);
						buffImg = ImageMerger.mergeOnRight(scaledImage, buffImg, imageParameters.getBackgroundColor(), imageParameters.getSignerTextImageVerticalAlignment());
						break;
					case TOP:
						scaledImage = writeImageToSignatureField(scaledImage, buffImg, imageParameters, true);
						buffImg = ImageMerger.mergeOnTop(scaledImage, buffImg, imageParameters.getBackgroundColor());
						break;
					case BOTTOM:
						scaledImage = writeImageToSignatureField(scaledImage, buffImg, imageParameters, true);
						buffImg = ImageMerger.mergeOnTop(buffImg, scaledImage, imageParameters.getBackgroundColor());
						break;
					default:
						throw new DSSException(String.format("The SignerNamePosition [%s] is not supported!", signerNamePosition.name()));
				}
			}
			
			return convertToInputStream(buffImg, CommonDrawerUtils.getDpi(imageParameters.getDpi()));
		}

		// Image only
		return ImageUtils.readDisplayMetadata(image);
	}
	
	private static BufferedImage createEmptyImage(final SignatureImageParameters imageParameters, final int textWidth, final int textHeight) {
		int width = 0;
		int height = 0;
		int fieldWidth = (int)CommonDrawerUtils.computeProperSize(imageParameters.getWidth(), imageParameters.getDpi());
		int fieldHeight = (int)CommonDrawerUtils.computeProperSize(imageParameters.getHeight(), imageParameters.getDpi());
		SignerPosition signerNamePosition = imageParameters.getTextParameters().getSignerNamePosition();
		switch (signerNamePosition) {
			case LEFT:
			case RIGHT:
				width = fieldWidth - textWidth;
				height = Math.max(fieldHeight, textHeight);
				break;
			case TOP:
			case BOTTOM:
				width = Math.max(fieldWidth, textWidth);
				height = fieldHeight - textHeight;
				break;
			default:
				throw new DSSException(String.format("The SignerNamePosition [%s] is not supported!", signerNamePosition.name()));
		}
		if (width > 0 && height > 0) {
			BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
			Graphics2D graphics2d = image.createGraphics();
			graphics2d.setComposite(AlphaComposite.Clear);
			graphics2d.fillRect(0, 0, width, height);
			graphics2d.dispose();
			return image;
		}
		return null;
	}
	
	/**
	 * Returns a scaled {@link BufferedImage} based on its dpi parameters relatively to page dpi
	 * @param image {@link DSSDocument} containing image to scale
	 * @param imageParameters {@link SignatureImageParameters}
	 * @return scaled {@link BufferedImage}
	 * @throws IOException in case of error
	 */
	private static BufferedImage getDpiScaledImage(DSSDocument image, SignatureImageParameters imageParameters) throws IOException {
		BufferedImage original = toBufferedImage(image);
		if (original == null) {
			return null;
		}
		try {
			ImageAndResolution imageAndResolution = ImageUtils.secureReadMetadata(image, imageParameters);
			float xScaleFactor = CommonDrawerUtils.getPageScaleFactor(imageAndResolution.getxDpi());
			xScaleFactor = CommonDrawerUtils.computeProperSize(xScaleFactor, CommonDrawerUtils.getDpi(imageParameters.getDpi()));
			float yScaleFactor = CommonDrawerUtils.getPageScaleFactor(imageAndResolution.getyDpi());
			yScaleFactor = CommonDrawerUtils.computeProperSize(yScaleFactor, CommonDrawerUtils.getDpi(imageParameters.getDpi()));
			return zoomImage(original, xScaleFactor, yScaleFactor);
		} catch (DSSException e) {
			LOG.warn("Cannot zoom image. Return the original : {}", e.getMessage());
			return original;
		}
	}
	
	private static BufferedImage toBufferedImage(DSSDocument image) throws IOException {
		try (InputStream is = image.openStream()) {
			if (is != null) {
				return ImageIO.read(is);
			}
			return null;
		}
	}
	
	private static BufferedImage writeImageToSignatureField(BufferedImage image, BufferedImage textImage, 
			SignatureImageParameters imageParameters, boolean verticalAlignment) {
		if (image == null) {
			return null;
		} else if (textImage == null) {
			return image;
		}
		
		int imageWidth = imageParameters.getWidth() == 0 ? image.getWidth() : imageParameters.getWidth();
		int imageHeight = imageParameters.getHeight() == 0 ? image.getHeight() : imageParameters.getHeight();
		
		int boxWidth = imageParameters.getWidth() == 0 ? imageWidth : (int)CommonDrawerUtils.computeProperSize(imageWidth, CommonDrawerUtils.getTextDpi());
		int boxHeight = imageParameters.getHeight() == 0 ? imageHeight : (int)CommonDrawerUtils.computeProperSize(imageHeight, CommonDrawerUtils.getTextDpi());
		
		if (imageParameters.getWidth() != 0) {
			imageWidth = verticalAlignment ? boxWidth : boxWidth - textImage.getWidth();
		} else {
			imageWidth = boxWidth;
		}
		if (imageParameters.getHeight() != 0) {
			imageHeight = (int)(verticalAlignment ? boxHeight - textImage.getHeight() : boxHeight);
		} else {
			imageHeight = boxHeight;
		}
		
		if (imageWidth < 1 || imageHeight < 1) {
			return null;
		}

		BufferedImage alignedImage = new BufferedImage(imageWidth, imageHeight, ImageUtils.getImageType(image));
		Graphics2D g = alignedImage.createGraphics();
		CommonDrawerUtils.initRendering(g);
		g.drawImage(image, 0, 0, imageWidth, imageHeight, null);
		
		return alignedImage;
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

	private static ImageWriter getImageWriter(String type) {
		Iterator<ImageWriter> writers = ImageIO.getImageWritersByFormatName(type);
		if (!writers.hasNext()) {
			throw new DSSException("No writer for '" + type + "' found");
		}
		return writers.next();
	}

}
