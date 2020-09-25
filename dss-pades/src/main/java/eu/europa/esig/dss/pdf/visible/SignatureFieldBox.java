package eu.europa.esig.dss.pdf.visible;

import java.awt.geom.Rectangle2D;

public interface SignatureFieldBox {
	
	/**
	 * Returns a signature field Rectangle, defining field position and dimension
	 * 
	 * @return {@link Rectangle2D}
	 */
	Rectangle2D getRectangle();

}
