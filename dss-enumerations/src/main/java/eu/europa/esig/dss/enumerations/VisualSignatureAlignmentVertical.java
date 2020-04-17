package eu.europa.esig.dss.enumerations;

/**
 * Visual signature vertical position on the pdf page
 */
public enum VisualSignatureAlignmentVertical {

	/**
	 * default, y axis is the y coordinate
	 */
	NONE,

	/**
	 * y axis is the top padding
	 */
	TOP,

	/**
	 * y axis automatically calculated
	 */
	MIDDLE,

	/**
	 * y axis is the bottom padding
	 */
	BOTTOM;

}
