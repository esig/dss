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
package eu.europa.esig.dss.pdf.pdfbox.visible.defaultdrawer;

import java.awt.image.BufferedImage;

import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.visible.VisualSignatureFieldAppearance;

public class SignatureImageAndPosition implements VisualSignatureFieldAppearance {

    private final float x;
    private final float y;
    private final float width;
    private final float height;

	private final BufferedImage signatureImage;
	
	public SignatureImageAndPosition(final float x, final float y, final float width, final float height, final BufferedImage signatureImage) {
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
        this.signatureImage = signatureImage;
    }

    public float getX() {
        return x;
    }

    public float getY() {
        return y;
    }
    
	public float getWidth() {
		return width;
	}

	public float getHeight() {
		return height;
	}

    public BufferedImage getSignatureImage() {
        return signatureImage;
    }

	@Override
	public AnnotationBox getAnnotationBox() {
		return new AnnotationBox(x, y, x + width, y + height);
	}
    
}
