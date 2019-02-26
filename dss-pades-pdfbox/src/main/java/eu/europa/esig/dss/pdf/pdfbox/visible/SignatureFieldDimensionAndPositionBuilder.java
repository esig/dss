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
		double width = imageAndDimension.getWidth();
		double height = imageAndDimension.getHeight();
		// if text is present
		SignatureImageTextParameters textParameters = imageParameters.getTextParameters();
		if (textParameters != null) {
			Font properFont = ImageTextWriter.computeProperFont(textParameters.getJavaFont(), textParameters.getSize(), imageParameters.getDpi());
			Dimension textBox = ImageTextWriter.computeSize(properFont, textParameters.getText(), textParameters.getMargin());
			dimensionAndPosition.setTextHeight(toDpiPagePoint(textBox.getHeight()));
			dimensionAndPosition.setTextWidth(toDpiPagePoint(textBox.getWidth()));
			switch (imageParameters.getTextParameters().getSignerNamePosition()) {
				case LEFT:
					dimensionAndPosition.setImageX((float) textBox.getWidth());
					width += textBox.getWidth();
					height = Math.max(height, textBox.getHeight());
					break;
				case RIGHT:
					dimensionAndPosition.setTextX((float) width);
					width += textBox.getWidth();
					height = Math.max(height, textBox.getHeight());
					break;
				case TOP:
					dimensionAndPosition.setImageY((float) textBox.getHeight());
					width = Math.max(width, textBox.getWidth());
					height += textBox.getHeight();
					break;
				case BOTTOM:
					dimensionAndPosition.setTextY((float) height);
					width = Math.max(width, textBox.getWidth());
					height += textBox.getHeight();
					break;
				default:
					break;
				}
			dimensionAndPosition.marginShift(toDpiPagePoint(textParameters.getMargin()));
		}
		dimensionAndPosition.setBoxWidth(toDpiPagePoint(width));
		dimensionAndPosition.setBoxHeight(toDpiPagePoint(height));
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
    
    private float toDpiPagePoint(double x) {
    	return CommonDrawerUtils.toDpiAxisPoint((float)x, imageParameters.getDpi());
    }
    
}
