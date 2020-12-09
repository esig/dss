package eu.europa.esig.dss.pdf.visible;

import eu.europa.esig.dss.pdf.AnnotationBox;

/**
 * Contains information about a visual SignatureField appearance
 *
 */
public interface VisualSignatureFieldAppearance {
	
	/**
	 * Creates an {@code AnnotationBox} from the SignatureFieldBox
	 * 
	 * @return {@link AnnotationBox}
	 */
	AnnotationBox getAnnotationBox();

}
