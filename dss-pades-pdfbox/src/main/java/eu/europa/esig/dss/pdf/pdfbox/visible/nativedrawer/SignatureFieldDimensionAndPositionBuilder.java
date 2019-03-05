package eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer;

import java.awt.Dimension;
import java.awt.Font;
import java.io.IOException;

import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.pades.SignatureImageParameters.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.pdfbox.visible.ImageRotationUtils;
import eu.europa.esig.dss.pdf.pdfbox.visible.ImageUtils;
import eu.europa.esig.dss.pdf.visible.CommonDrawerUtils;
import eu.europa.esig.dss.pdf.visible.FontUtils;
import eu.europa.esig.dss.pdf.visible.ImageAndResolution;

public class SignatureFieldDimensionAndPositionBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(SignatureFieldDimensionAndPositionBuilder.class);
	
	private SignatureFieldDimensionAndPosition dimensionAndPosition;
	private final SignatureImageParameters imageParameters;
	private final PDPage page;
	private final PDRectangle pageMediaBox;
	
    private static final String SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE = "not supported vertical alignment: ";
    private static final String SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE = "not supported horizontal alignment: ";
	
    public SignatureFieldDimensionAndPositionBuilder(SignatureImageParameters imageParameters, PDPage page) {
		this.imageParameters = imageParameters;
		this.page = page;
		this.pageMediaBox = page.getMediaBox();
	}
	
	public SignatureFieldDimensionAndPosition build() throws IOException {
		this.dimensionAndPosition = new SignatureFieldDimensionAndPosition();
		initDpi();
		assignImageBoxDimension();
		alignHorizontally();
		alignVertically();
		rotateSignatureField();
		return this.dimensionAndPosition;
	}
	
	private void initDpi() throws IOException {
		if (imageParameters.getImage() != null) {
			ImageAndResolution imageAndResolution;
			try {
				imageAndResolution = ImageUtils.readDisplayMetadata(imageParameters.getImage());
			} catch (Exception e) {
				LOG.warn("Cannot access the image metadata : {}. Returns default info.", e.getMessage());
				imageAndResolution = new ImageAndResolution(imageParameters.getImage(), imageParameters.getDpi(), imageParameters.getDpi());
			}
			dimensionAndPosition.setImageAndResolution(imageAndResolution);
		}
	}
	
	private void assignImageBoxDimension() {
		Dimension imageAndDimension = ImageUtils.getImageDimension(imageParameters);
		double imageWidth = imageAndDimension.getWidth();
		double imageHeight = imageAndDimension.getHeight();
		double width = imageWidth;
		double height = imageHeight;
		SignatureImageTextParameters textParameters = imageParameters.getTextParameters();
		// if text is present
		if (textParameters != null) {
			Font properFont = FontUtils.computeProperFont(textParameters.getJavaFont(), textParameters.getSize(), imageParameters.getDpi());
			Dimension textBox = FontUtils.computeSize(properFont, textParameters.getText(), textParameters.getMargin());
			float textWidth = (float) textBox.getWidth() / CommonDrawerUtils.getScaleFactor(dimensionAndPosition.getxDpi());
			float textHeight = (float) textBox.getHeight() / CommonDrawerUtils.getScaleFactor(dimensionAndPosition.getyDpi());
			switch (imageParameters.getTextParameters().getSignerNamePosition()) {
				case LEFT:
					width += textWidth;
					height = Math.max(height, textHeight);
					dimensionAndPosition.setImageX((float)(width - imageWidth));
					textImageVerticalAlignment((float)height, (float)imageHeight, textHeight);
					break;
				case RIGHT:
					width += textWidth;
					height = Math.max(height, textHeight);
					dimensionAndPosition.setTextX(toDpiPagePoint((float)imageWidth, dimensionAndPosition.getxDpi()));
					textImageVerticalAlignment((float)height, (float)imageHeight, textHeight);
					break;
				case TOP:
					width = Math.max(width, textWidth);
					height += textHeight;
					dimensionAndPosition.setTextY(toDpiPagePoint((float)imageHeight, dimensionAndPosition.getyDpi()));
					dimensionAndPosition.setTextX(toDpiPagePoint((float)(width - textWidth)/2, dimensionAndPosition.getxDpi()));
					dimensionAndPosition.setImageX((float)(width - imageWidth)/2);
					break;
				case BOTTOM:
					width = Math.max(width, textWidth);
					height += textHeight;
					dimensionAndPosition.setImageY((float)(height - imageHeight));
					dimensionAndPosition.setTextX(toDpiPagePoint((float)(width - textWidth)/2, dimensionAndPosition.getxDpi()));
					dimensionAndPosition.setImageX((float)(width - imageWidth)/2);
					break;
				default:
					break;
				}
			dimensionAndPosition.setTextWidth(toDpiPagePoint(textWidth, dimensionAndPosition.getxDpi()));
			dimensionAndPosition.setTextHeight(toDpiPagePoint(textHeight, dimensionAndPosition.getyDpi()));
			dimensionAndPosition.marginShift(textParameters.getMargin());
		}
		dimensionAndPosition.setBoxWidth(toDpiPagePoint(width, dimensionAndPosition.getxDpi()));
		dimensionAndPosition.setBoxHeight(toDpiPagePoint(height, dimensionAndPosition.getyDpi()));
	}
	
	private void textImageVerticalAlignment(Float height, float imageHeight, float textHeight) {
		switch (imageParameters.getSignerTextImageVerticalAlignment()) {
			case TOP:
				dimensionAndPosition.setTextY(toDpiPagePoint((height - textHeight), dimensionAndPosition.getyDpi()));
				dimensionAndPosition.setImageY(height - imageHeight);
				break;
			case BOTTOM:
				dimensionAndPosition.setTextY(0);
				dimensionAndPosition.setImageY(0);
				break;
			case MIDDLE:
			default:
				dimensionAndPosition.setTextY(toDpiPagePoint((height - textHeight)/2, dimensionAndPosition.getyDpi()));
				dimensionAndPosition.setImageY((height - imageHeight)/2);
				break;
		}
	}
	
	private void alignHorizontally() {
		VisualSignatureAlignmentHorizontal alignmentHorizontal = imageParameters.getVisualSignatureAlignmentHorizontal();
		float boxX;
		switch (alignmentHorizontal) {
			case LEFT:
			case NONE:
				boxX = imageParameters.getxAxis();
				break;
			case CENTER:
				boxX = (pageMediaBox.getWidth() - dimensionAndPosition.getBoxWidth()) / 2;
				break;
			case RIGHT:
				boxX = pageMediaBox.getWidth() - dimensionAndPosition.getBoxWidth() - imageParameters.getxAxis();
				break;
			default:
				throw new IllegalStateException(SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal.name());
		}
		dimensionAndPosition.setBoxX(boxX);
	}
	
	private void alignVertically() {
		VisualSignatureAlignmentVertical alignmentVertical = imageParameters.getVisualSignatureAlignmentVertical();
		float boxY;
		switch (alignmentVertical) {
		case TOP:
		case NONE:
			boxY = imageParameters.getyAxis();
			break;
		case MIDDLE:
			boxY = (pageMediaBox.getHeight() - dimensionAndPosition.getBoxHeight()) / 2;
			break;
		case BOTTOM:
			boxY = pageMediaBox.getHeight() - dimensionAndPosition.getBoxHeight() - imageParameters.getyAxis();
			break;
		default:
			throw new IllegalStateException(SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical.name());
		}
		dimensionAndPosition.setBoxY(boxY);
	}
	
	private void rotateSignatureField() {
		int rotate = ImageRotationUtils.getRotation(imageParameters.getRotation(), page);
		switch (rotate) {
			case ImageRotationUtils.ANGLE_90:
				swapDimension();
				float boxX = dimensionAndPosition.getBoxX();
				dimensionAndPosition.setBoxX(pageMediaBox.getWidth() - dimensionAndPosition.getBoxY() -
						dimensionAndPosition.getBoxWidth());
				dimensionAndPosition.setBoxY(boxX);
				break;
			case ImageRotationUtils.ANGLE_180:
				dimensionAndPosition.setBoxX(pageMediaBox.getWidth() - dimensionAndPosition.getBoxX() -
						dimensionAndPosition.getBoxWidth());
				dimensionAndPosition.setBoxY(pageMediaBox.getHeight() - dimensionAndPosition.getBoxY() -
						dimensionAndPosition.getBoxHeight());
				break;
			case ImageRotationUtils.ANGLE_270:
				swapDimension();
				boxX = dimensionAndPosition.getBoxX();
				dimensionAndPosition.setBoxX(dimensionAndPosition.getBoxY());
				dimensionAndPosition.setBoxY(pageMediaBox.getHeight() - boxX -
						dimensionAndPosition.getBoxHeight());
				break;
			case ImageRotationUtils.ANGLE_360:
				// do nothing
				break;
			default:
	            throw new IllegalStateException(ImageRotationUtils.SUPPORTED_ANGLES_ERROR_MESSAGE);
		}
	}
	
	private void swapDimension() {
		float temp = dimensionAndPosition.getBoxWidth();
		dimensionAndPosition.setBoxWidth(dimensionAndPosition.getBoxHeight());
		dimensionAndPosition.setBoxHeight(temp);
	}
    
    private float toDpiPagePoint(double x, Integer dpi) {
    	return CommonDrawerUtils.toDpiAxisPoint((float)x, CommonDrawerUtils.getDpi(dpi));
    }
    
}
