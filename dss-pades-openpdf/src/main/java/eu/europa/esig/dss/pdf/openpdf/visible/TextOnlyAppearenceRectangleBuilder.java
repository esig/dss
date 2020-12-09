package eu.europa.esig.dss.pdf.openpdf.visible;

import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.AnnotationBox;

public class TextOnlyAppearenceRectangleBuilder extends ITextAppearanceRectangleBuilder {

	private final ITextFontMetrics iTextFontMetrics;
	private final float properSize;

	protected TextOnlyAppearenceRectangleBuilder(SignatureImageParameters imageParameters,
			ITextFontMetrics iTextFontMetrics, float properSize) {
		super(imageParameters);
		this.iTextFontMetrics = iTextFontMetrics;
		this.properSize = properSize;
	}

	@Override
	public ITextVisualSignatureAppearance build() {
		SignatureFieldParameters fieldParameters = imageParameters.getFieldParameters();
		float width = fieldParameters.getWidth();
		float height = fieldParameters.getHeight();
		if (width == 0 || height == 0) {
			SignatureImageTextParameters textParameters = imageParameters.getTextParameters();
			AnnotationBox textBox = iTextFontMetrics.computeTextBoundaryBox(textParameters.getText(), properSize,
					textParameters.getPadding());

			width = textBox.getWidth();
			height = textBox.getHeight();
		}

		return new ITextVisualSignatureAppearance(fieldParameters.getOriginX(), fieldParameters.getOriginY(),
				fieldParameters.getOriginX() + width, fieldParameters.getOriginY() + height);
	}

}
