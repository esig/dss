/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pdf.visible;

import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.pdf.AnnotationBox;

/**
 * Contains utils for the image rotation
 *
 */
public class ImageRotationUtils {

    /** A message with supported angles */
	public static final String SUPPORTED_ANGLES_ERROR_MESSAGE = "rotation angle must be 90, 180, 270 or 360 (0)";

	/** Default 0 degrees */
    public static final int ANGLE_0 = 0;
    /** 90 degrees */
    public static final int ANGLE_90 = 90;
    /** 180 degrees */
	public static final int ANGLE_180 = 180;
    /** 270 degrees */
	public static final int ANGLE_270 = 270;
    /** 360 degrees (= 0 degrees) */
    public static final int ANGLE_360 = 360;

    /**
     * Utils class
     */
	private ImageRotationUtils() {
	}
	
	private static boolean needRotation(VisualSignatureRotation visualSignatureRotation) {
		return visualSignatureRotation != null && !VisualSignatureRotation.NONE.equals(visualSignatureRotation);
    }
    
    /**
     * Returns rotation parameter not depending on the page rotation
     *
     * @param visualSignatureRotation {@link VisualSignatureRotation}
     * @return int rotation angle
     */
    public static int getRotation(VisualSignatureRotation visualSignatureRotation) {
    	return getRotation(visualSignatureRotation, 0);
    }

    /**
     * Returns rotation based on the page's default rotation parameter
     *
     * @param visualSignatureRotation {@link VisualSignatureRotation}
     * @param pageRotation the rotation of a page
     * @return int rotation angle
     */
    public static int getRotation(VisualSignatureRotation visualSignatureRotation, int pageRotation) {
        int rotate = ANGLE_360;
        if (needRotation(visualSignatureRotation)) {
            switch (visualSignatureRotation) {
                case AUTOMATIC:
                    rotate = ANGLE_360 - pageRotation;
                    break;
                case ROTATE_90:
                    rotate = ANGLE_90;
                    break;
                case ROTATE_180:
                    rotate = ANGLE_180;
                    break;
                case ROTATE_270:
                    rotate = ANGLE_270;
                    break;
                default:
                    throw new IllegalStateException(SUPPORTED_ANGLES_ERROR_MESSAGE);
            }
        }
        return rotate;
    }

    /**
     * Verifies if swap of dimensions is required with the current rotation
     *
     * @param rotation {@code int} rotation degree
     * @return TRUE is swap of dimensions is required, FALSE otherwise
     */
    public static boolean isSwapOfDimensionsRequired(int rotation) {
    	return ImageRotationUtils.ANGLE_90 == rotation || ImageRotationUtils.ANGLE_270 == rotation;
    }

    /**
     * Verifies if swap of dimensions is required with the current rotation
     *
     * @param rotation {@code VisualSignatureRotation}
     * @return TRUE is swap of dimensions is required, FALSE otherwise
     */
    public static boolean isSwapOfDimensionsRequired(VisualSignatureRotation rotation) {
        return VisualSignatureRotation.ROTATE_90 == rotation || VisualSignatureRotation.ROTATE_270 == rotation;
    }

    /**
     * This method swaps dimensions of the given {@code AnnotationBox}
     *
     * @param annotationBox {@link AnnotationBox}
     * @return {@link AnnotationBox}
     */
    public static AnnotationBox swapDimensions(AnnotationBox annotationBox) {
        return new AnnotationBox(annotationBox.getMinY(), annotationBox.getMinX(), annotationBox.getMaxY(), annotationBox.getMaxX());
    }

    /**
     * This method rotates the given {@code annotationBox} relatively the {@code wrappingBox}
     * according to the given {@code rotation}
     *
     * @param annotationBox {@link AnnotationBox} to rotate
     * @param wrappingBox {@link AnnotationBox} representing wrapping box
     * @param rotation rotation degree
     * @return {@link AnnotationBox}
     */
    public static AnnotationBox rotateRelativelyWrappingBox(AnnotationBox annotationBox, AnnotationBox wrappingBox, int rotation) {
        switch (rotation) {
            case ImageRotationUtils.ANGLE_90:
                return new AnnotationBox(annotationBox.getMinY(),
                        wrappingBox.getWidth() - annotationBox.getMaxX(),
                        annotationBox.getMaxY(),
                        wrappingBox.getWidth() - annotationBox.getMinX());
            case ImageRotationUtils.ANGLE_180:
                return new AnnotationBox(wrappingBox.getWidth() - annotationBox.getMaxX(),
                        wrappingBox.getHeight() - annotationBox.getMaxY(),
                        wrappingBox.getWidth() - annotationBox.getMinX(),
                        wrappingBox.getHeight() - annotationBox.getMinY());
            case ImageRotationUtils.ANGLE_270:
                return new AnnotationBox(wrappingBox.getHeight() - annotationBox.getMaxY(),
                        annotationBox.getMinX(),
                        wrappingBox.getHeight() - annotationBox.getMinY(),
                        annotationBox.getMaxX());
            case ImageRotationUtils.ANGLE_0:
            case ImageRotationUtils.ANGLE_360:
                // do nothing
                return annotationBox;
            default:
                throw new IllegalStateException(ImageRotationUtils.SUPPORTED_ANGLES_ERROR_MESSAGE);
        }
    }

    /**
     * This method is used to ensure the annotation wrapping box defines correct coordinates relatively the "noRotate" flag
     *
     * @param annotationBox {@link AnnotationBox} containing coordinates extracted from PDF document
     * @param pageRotation the page rotation degree
     * @return {@link AnnotationBox} with coordinates for the "noRotate" flag annotation relatively the page's rotation
     */
    public static AnnotationBox ensureNoRotate(AnnotationBox annotationBox, int pageRotation) {
        switch (pageRotation) {
            case ImageRotationUtils.ANGLE_90:
                return new AnnotationBox(
                        annotationBox.getMinX(),
                        annotationBox.getMaxY(),
                        annotationBox.getMinX() + annotationBox.getHeight(),
                        annotationBox.getMaxY() + annotationBox.getWidth());
            case ImageRotationUtils.ANGLE_180:
                return new AnnotationBox(
                        annotationBox.getMinX() - annotationBox.getWidth(),
                        annotationBox.getMaxY(),
                        annotationBox.getMinX(),
                        annotationBox.getMaxY() + annotationBox.getHeight());
            case ImageRotationUtils.ANGLE_270:
                return new AnnotationBox(
                        annotationBox.getMinX() - annotationBox.getHeight(),
                        annotationBox.getMaxY() - annotationBox.getWidth(),
                        annotationBox.getMinX(),
                        annotationBox.getMaxY());
            case ImageRotationUtils.ANGLE_0:
            case ImageRotationUtils.ANGLE_360:
                return annotationBox;
            default:
                throw new UnsupportedOperationException(
                        String.format("The rotation degree '%s' is not supported!", pageRotation));
        }
    }
    
}
