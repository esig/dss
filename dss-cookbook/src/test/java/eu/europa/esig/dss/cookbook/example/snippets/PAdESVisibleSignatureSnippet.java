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
package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.enumerations.ImageScaling;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxNativeFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;

import java.awt.Color;

public class PAdESVisibleSignatureSnippet {
	
	public void demo() {

		// tag::visibleSigParams[]
		// Instantiate PAdES-specific parameters
		PAdESSignatureParameters padesSignatureParameters = new PAdESSignatureParameters();
		
		// tag::positioning[]
		
		// Object containing a list of visible signature parameters
		SignatureImageParameters signatureImageParameters = new SignatureImageParameters();
		
		// Allows alignment of a signature field horizontally to a page. Allows the following values:
		/* _NONE_ (_DEFAULT value._ None alignment is applied, coordinates are counted from the left page side);
		   _LEFT_ (the signature is aligned to the left side, coordinated are counted from the left page side);
		   _CENTER_ (the signature is aligned to the center of the page, coordinates are counted automatically);
		   _RIGHT_ (the signature is aligned to the right side, coordinated are counted from the right page side). */
		signatureImageParameters.setAlignmentHorizontal(VisualSignatureAlignmentHorizontal.CENTER);
		
		// Allows alignment of a signature field vertically to a page. Allows the following values:
		/* _NONE_ (_DEFAULT value._ None alignment is applied, coordinated are counted from the top side of a page);
		   _TOP_ (the signature is aligned to a top side, coordinated are counted from the top page side);
		   _MIDDLE_ (the signature aligned to a middle of a page, coordinated are counted automatically);
		   _BOTTOM_ (the signature is aligned to a bottom side, coordinated are counted from the bottom page side). */
		signatureImageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.TOP);
		
		// Rotates the signature field and changes the coordinates' origin respectively to its values as following:
		/* _NONE_ (_DEFAULT value._ No rotation is applied. The origin of coordinates begins from the top left corner of a page);
		   _AUTOMATIC_ (Rotates a signature field respectively to the page's rotation. Rotates the signature field on the same value as a defined in a PDF page);
		   _ROTATE_90_ (Rotates a signature field for a 90&#176; clockwise. Coordinates' origin begins from top right page corner);
		   _ROTATE_180_ (Rotates a signature field for a 180&#176; clockwise. Coordinates' origin begins from the bottom right page corner);
		   _ROTATE_270_ (Rotates a signature field for a 270&#176; clockwise. Coordinates' origin begins from the bottom left page corner). */
		signatureImageParameters.setRotation(VisualSignatureRotation.AUTOMATIC);
		
		// Defines a zoom of the image. The value is applied to width and height of a signature field. 
		// The value must be defined in percentage (default value is 100, no zoom is applied).
		signatureImageParameters.setZoom(50);
		
		// Specifies a background color for a signature field.
		signatureImageParameters.setBackgroundColor(Color.GREEN);
		
		// Defines the image scaling behavior within a signature field with a fixed size
		/*
		  STRETCH - the default behavior, stretches the image in both directions in order to fill the signature field box;
		  ZOOM_AND_CENTER - zooms the image to fill the signature box to the closest side, and centers in another dimension;
		  CENTER - centers the image in both dimensions.
		*/
		signatureImageParameters.setImageScaling(ImageScaling.CENTER);

		// set the image parameters to signature parameters
		padesSignatureParameters.setImageParameters(signatureImageParameters);
		
		// end::positioning[]
		
		// tag::dimensions[]
		
		// Object containing a list of signature field parameters
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		signatureImageParameters.setFieldParameters(fieldParameters);
		
		// Allows defining of a specific page in a PDF document where the signature must be placed. 
		// The counting of pages starts from 1 (the first page) 
		// (the default value = 1).
		fieldParameters.setPage(1);
		
		// Absolute positioning functions, allowing to specify a margin between 
		// the left page side and the top page side respectively, and
		// a signature field (if no rotation and alignment is applied).
		fieldParameters.setOriginX(10);
		fieldParameters.setOriginY(10);
		
		// Allows specifying of a precise signature field's width in pixels. 
		// If not defined, the default image/text width will be used.
		fieldParameters.setWidth(100);
		
		// Allows specifying of a precise signature field's height in pixels. 
		// If not defined, the default image/text height will be used.
		fieldParameters.setHeight(125);
		
		// end::dimensions[]
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		// tag::nativeFont[]
		
		textParameters.setFont(new PdfBoxNativeFont(PDType1Font.HELVETICA));
		
		// end::nativeFont[]
		// end::visibleSigParams[]
		
	}

}
