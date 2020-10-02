package eu.europa.esig.dss.pdf.visible;

import eu.europa.esig.dss.pdf.AnnotationBox;

/**
 * Defines a SignatureField position and dimension
 *
 */
public interface SignatureFieldBox {
	
	/**
	 * Creates an {@code AnnotationBox} from the SignatureFieldBox
	 * 
	 * @return {@link AnnotationBox}
	 */
	public AnnotationBox toAnnotationBox();

}
