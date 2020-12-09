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
package eu.europa.esig.dss.pdf.pdfbox.visible;

import org.apache.pdfbox.pdmodel.PDPage;

import eu.europa.esig.dss.enumerations.VisualSignatureRotation;

/**
 * Contains utils for the image rotation
 */
public class ImageRotationUtils {
	
	public static final String SUPPORTED_ANGLES_ERROR_MESSAGE = "rotation angle must be 90, 180, 270 or 360 (0)";

	public static final int ANGLE_360 = 360;
	public static final int ANGLE_90 = 90;
	public static final int ANGLE_180 = 180;
	public static final int ANGLE_270 = 270;
	
	private ImageRotationUtils() {
	}
	
	private static boolean needRotation(VisualSignatureRotation visualSignatureRotation) {
		return visualSignatureRotation != null && !VisualSignatureRotation.NONE.equals(visualSignatureRotation);
    }
    
    /**
     * Returns rotation parameter not depending on the page rotation
     * @param visualSignatureRotation {@link VisualSignatureRotation}
     * @return int rotation angle
     */
    public static int getRotation(VisualSignatureRotation visualSignatureRotation) {
    	return getRotation(visualSignatureRotation, 0);
    }

    /**
     * Returns rotation based on the page's default rotation parameter
     * @param visualSignatureRotation {@link VisualSignatureRotation}
     * @param pdPage {@link PDPage} to get default rotation from
     * @return int rotation angle
     */
    public static int getRotation(VisualSignatureRotation visualSignatureRotation, PDPage pdPage) {
        return getRotation(visualSignatureRotation, pdPage.getRotation());
    }
    
    private static int getRotation(VisualSignatureRotation visualSignatureRotation, int pageDefaultRotation) {
        int rotate = ANGLE_360;

        if(needRotation(visualSignatureRotation)) {
            switch (visualSignatureRotation) {
                case AUTOMATIC:
                    rotate = ANGLE_360 - pageDefaultRotation;
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
     * @param rotation {@code int} rotation degree
     * @return TRUE is swap of dimensions is required, FALSE otherwise
     */
    public static boolean isSwapOfDimensionsRequired(int rotation) {
    	return ImageRotationUtils.ANGLE_90 == rotation || ImageRotationUtils.ANGLE_270 == rotation;
    }
    
}
