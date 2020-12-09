package eu.europa.esig.dss.pdf.openpdf.visible;

import com.lowagie.text.Image;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pdf.visible.CommonDrawerUtils;
import eu.europa.esig.dss.pdf.visible.ImageAndResolution;
import eu.europa.esig.dss.pdf.visible.ImageUtils;

import java.io.IOException;

/**
 * Creates a {@code VisualSignatureFieldAppearance} for an image only visual signature
 */
public class ImageOnlyAppearanceRectangleBuilder extends ITextAppearanceRectangleBuilder {

	/** The image to create */
	private final Image image;

	/**
	 * Default constructor
	 *
	 * @param imageParameters {@link SignatureImageParameters}
	 * @param image {@link Image}
	 */
	protected ImageOnlyAppearanceRectangleBuilder(SignatureImageParameters imageParameters, Image image) {
		super(imageParameters);
		this.image = image;
	}

	@Override
	public ITextVisualSignatureAppearance build() throws IOException {
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
		
		return new ITextVisualSignatureAppearance(
				fieldParameters.getOriginX(),
				fieldParameters.getOriginY(),
				fieldParameters.getOriginX() + width, 
				fieldParameters.getOriginY() + height
				);
	}

}
