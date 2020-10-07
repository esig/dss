package eu.europa.esig.dss.pdf.openpdf.visible;

import java.awt.Dimension;

import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;

public class TextOnlyAppearenceRectangleBuilder extends ITextAppearenceRectangleBuilder {
	
	private final ITextFontMetrics iTextFontMetrics;
	private final float properSize;

	protected TextOnlyAppearenceRectangleBuilder(SignatureImageParameters imageParameters,
			ITextFontMetrics iTextFontMetrics, float properSize) {
		super(imageParameters);
		this.iTextFontMetrics = iTextFontMetrics;
		this.properSize = properSize;
	}

	@Override
	public ITextVisualSignatureAppearence build() {
		SignatureFieldParameters fieldParameters = imageParameters.getFieldParameters();
		float width = fieldParameters.getWidth();
		float height = fieldParameters.getHeight();
		if (width == 0 || height == 0) {
			SignatureImageTextParameters textParameters = imageParameters.getTextParameters();
			Dimension dimension = iTextFontMetrics.computeDimension(textParameters.getText(), properSize, textParameters.getPadding());
			
			width = dimension.width;
			height = dimension.height;
		}
		
		return new ITextVisualSignatureAppearence(
				fieldParameters.getOriginX(),
				fieldParameters.getOriginY(),
				fieldParameters.getOriginX() + width, 
				fieldParameters.getOriginY() + height
				);
	}

}
