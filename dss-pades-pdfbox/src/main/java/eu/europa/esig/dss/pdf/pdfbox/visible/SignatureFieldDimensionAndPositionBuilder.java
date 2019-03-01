package eu.europa.esig.dss.pdf.pdfbox.visible;

import java.awt.Dimension;
import java.awt.Font;
import java.io.IOException;

import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;

import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.pades.SignatureImageParameters.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.visible.CommonDrawerUtils;
import eu.europa.esig.dss.pdf.visible.ImageTextWriter;
import eu.europa.esig.dss.pdf.visible.ImageUtils;

public class SignatureFieldDimensionAndPositionBuilder {
	
	private SignatureFieldDimensionAndPosition dimensionAndPosition;
	private final SignatureImageParameters imageParameters;
	private final PDRectangle pageMediaBox;
	
    private static final String SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE = "not supported vertical alignment: ";
    private static final String SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE = "not supported horizontal alignment: ";
	
    public SignatureFieldDimensionAndPositionBuilder(SignatureImageParameters imageParameters, PDPage page) {
		this.imageParameters = imageParameters;
		this.pageMediaBox = page.getMediaBox();
	}
	
	public SignatureFieldDimensionAndPosition build() throws IOException {
		this.dimensionAndPosition = new SignatureFieldDimensionAndPosition();
		initDpi();
		assignImageBoxDimension();
		alignHorizontally();
		alignVertically();
		return this.dimensionAndPosition;
	}
	
	private void initDpi() throws IOException {
		if (imageParameters.getImage() != null) {
			dimensionAndPosition.setImageAndResolution(ImageUtils.readDisplayMetadata(imageParameters.getImage()));
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
			Font properFont = ImageTextWriter.computeProperFont(textParameters.getJavaFont(), textParameters.getSize(), imageParameters.getDpi());
			Dimension textBox = ImageTextWriter.computeSize(properFont, textParameters.getText(), textParameters.getMargin());
			float textWidth = (float) textBox.getWidth() / CommonDrawerUtils.getScaleFactor(dimensionAndPosition.getxDpi());
			float textHeight = (float) textBox.getHeight() / CommonDrawerUtils.getScaleFactor(dimensionAndPosition.getyDpi());
			switch (imageParameters.getTextParameters().getSignerNamePosition()) {
				case LEFT:
					width += textWidth;
					height = Math.max(height, textHeight);
					dimensionAndPosition.setImageX(textWidth);
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
					dimensionAndPosition.setImageY(textHeight);
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
		VisualSignatureAlignmentHorizontal alignmentHorizontal = getVisualSignatureAlignmentHorizontal();
		float boxX;
		switch (alignmentHorizontal) {
			case LEFT:
			case NONE:
				boxX = imageParameters.getxAxis();
				break;
			case CENTER:
				boxX = (pageMediaBox.getWidth() - CommonDrawerUtils.toDpiAxisPoint(dimensionAndPosition.getBoxWidth(), 
						dimensionAndPosition.getxDpi())) / 2;
				break;
			case RIGHT:
				boxX = pageMediaBox.getWidth() - CommonDrawerUtils.toDpiAxisPoint(dimensionAndPosition.getBoxWidth(), 
						dimensionAndPosition.getxDpi()) - imageParameters.getxAxis();
				break;
			default:
				throw new IllegalStateException(SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal.name());
		}
		dimensionAndPosition.setBoxX(boxX);
	}
	
	private void alignVertically() {
		VisualSignatureAlignmentVertical alignmentVertical = getVisualSignatureAlignmentVertical();
		float boxY;
		switch (alignmentVertical) {
		case TOP:
		case NONE:
			boxY = imageParameters.getyAxis();
			break;
		case MIDDLE:
			boxY = (pageMediaBox.getHeight() - CommonDrawerUtils.toDpiAxisPoint(dimensionAndPosition.getBoxHeight(), 
					dimensionAndPosition.getyDpi())) / 2;
			break;
		case BOTTOM:
			boxY = pageMediaBox.getHeight() - CommonDrawerUtils.toDpiAxisPoint(dimensionAndPosition.getBoxHeight(), 
					dimensionAndPosition.getyDpi()) - imageParameters.getyAxis();
			break;
		default:
			throw new IllegalStateException(SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical.name());
		}
		dimensionAndPosition.setBoxY(boxY);
	}

    private SignatureImageParameters.VisualSignatureAlignmentHorizontal getVisualSignatureAlignmentHorizontal() {
        SignatureImageParameters.VisualSignatureAlignmentHorizontal alignmentHorizontal = imageParameters.getAlignmentHorizontal();
        if(alignmentHorizontal == null) {
            alignmentHorizontal = SignatureImageParameters.VisualSignatureAlignmentHorizontal.NONE;
        }

        return alignmentHorizontal;
    }
	
    private SignatureImageParameters.VisualSignatureAlignmentVertical getVisualSignatureAlignmentVertical() {
        SignatureImageParameters.VisualSignatureAlignmentVertical alignmentVertical = imageParameters.getAlignmentVertical();
        if(alignmentVertical == null) {
            alignmentVertical = SignatureImageParameters.VisualSignatureAlignmentVertical.NONE;
        }

        return alignmentVertical;
    }
    
    private float toDpiPagePoint(double x, Integer dpi) {
    	return CommonDrawerUtils.toDpiAxisPoint((float)x, CommonDrawerUtils.getDpi(dpi));
    }
    
}
