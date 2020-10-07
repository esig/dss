package eu.europa.esig.dss.pdf.openpdf.visible;

import java.io.IOException;

import com.lowagie.text.Image;

import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pdf.visible.CommonDrawerUtils;
import eu.europa.esig.dss.pdf.visible.ImageAndResolution;
import eu.europa.esig.dss.pdf.visible.ImageUtils;

public class ImageOnlyAppearenceRectangleBuilder extends ITextAppearenceRectangleBuilder {
	
	private final Image image;

	protected ImageOnlyAppearenceRectangleBuilder(SignatureImageParameters imageParameters, Image image) {
		super(imageParameters);
		this.image = image;
	}

	@Override
	public ITextVisualSignatureAppearence build() throws IOException {
		float zoom = ImageUtils.getScaleFactor(imageParameters.getZoom());
		
		SignatureFieldParameters fieldParameters = imageParameters.getFieldParameters();
		float width = fieldParameters.getWidth();
		float height = fieldParameters.getHeight();
		
		ImageAndResolution ires = ImageUtils.readDisplayMetadata(imageParameters.getImage());
		if (width == 0) {
			width = (int) (image.getWidth() * CommonDrawerUtils.getPageScaleFactor(ires.getxDpi()));
		}
		if (height == 0) {
			height = (int) (image.getHeight() * CommonDrawerUtils.getPageScaleFactor(ires.getyDpi()));
		}
		width *= zoom;
		height *= zoom;
		
		return new ITextVisualSignatureAppearence(
				fieldParameters.getOriginX(),
				fieldParameters.getOriginY(),
				fieldParameters.getOriginX() + width, 
				fieldParameters.getOriginY() + height
				);
	}

}
