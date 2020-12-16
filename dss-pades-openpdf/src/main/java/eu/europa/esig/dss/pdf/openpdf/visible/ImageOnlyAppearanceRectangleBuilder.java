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
