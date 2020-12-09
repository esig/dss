package eu.europa.esig.dss.pdf.openpdf.visible;

import eu.europa.esig.dss.pades.SignatureImageParameters;

import java.io.IOException;

/**
 * This class builds a {@code VisualSignatureFieldAppearance} for an IText Signature Drawer
 *
 */
public abstract class ITextAppearanceRectangleBuilder {

	/** The visual signature parameters */
	protected final SignatureImageParameters imageParameters;
	
	/**
	 * The default constructor
	 * 
	 * @param imageParameters {@link SignatureImageParameters}
	 */
	protected ITextAppearanceRectangleBuilder(SignatureImageParameters imageParameters) {
		this.imageParameters = imageParameters;
	}
	
	/**
	 * Builds and returns {@code VisualSignatureFieldAppearance}
	 * 
	 * @return {@link ITextVisualSignatureAppearance}
	 * @throws IOException if an exception occurs
	 */
	public abstract ITextVisualSignatureAppearance build() throws IOException;

}
