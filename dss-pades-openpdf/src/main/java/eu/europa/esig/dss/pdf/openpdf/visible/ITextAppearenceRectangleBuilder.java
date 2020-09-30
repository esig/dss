package eu.europa.esig.dss.pdf.openpdf.visible;

import java.io.IOException;

import eu.europa.esig.dss.pades.SignatureImageParameters;

/**
 * This class builds an {@code AppearenceRectangle} for an IText Signature Drawer
 *
 */
public abstract class ITextAppearenceRectangleBuilder {
	
	protected final SignatureImageParameters imageParameters;
	
	/**
	 * The default constructor
	 * 
	 * @param imageParameters {@link SignatureImageParameters}
	 */
	protected ITextAppearenceRectangleBuilder(SignatureImageParameters imageParameters) {
		this.imageParameters = imageParameters;
	}
	
	/**
	 * Builds and returns {@code AppearenceRectangle}
	 * 
	 * @return {@link AppearenceRectangle}
	 * @throws IOException if an exception occurs
	 */
	public abstract AppearenceRectangle build() throws IOException;

}
