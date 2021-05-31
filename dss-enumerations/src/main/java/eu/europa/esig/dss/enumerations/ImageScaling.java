package eu.europa.esig.dss.enumerations;

/**
 * This class defines an enumeration that can be used to define the image scaling behavior
 * for signature fields with a fixed size
 *
 */
public enum ImageScaling {

    /** Stretches the image in both directions in order to fill the signature field box */
    STRETCH,

    /** Zooms the image to the closest dimension without stretching and centers the image in other direction */
    ZOOM_AND_CENTER,

    /** Keeps the original image size and centers the image in both directions */
    CENTER;

}
