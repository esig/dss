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
package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.enumerations.SignerTextVerticalAlignment;
import eu.europa.esig.dss.utils.Utils;

import java.awt.*;
import java.io.Serializable;

/**
 * This class allows to custom text generation in the PAdES visible signature
 *
 */
public class SignatureImageTextParameters implements Serializable {

	private static final long serialVersionUID = 727438728149346847L;

	/** The default background color (white) */
	private static final Color DEFAULT_BACKGROUND_COLOR = Color.WHITE;

	/** The default padding (5 pixels) */
	private static final float DEFAULT_PADDING = 5f;

	/** The default text color (black) */
	private static final Color DEFAULT_TEXT_COLOR = Color.BLACK;

	/**
	 * This variable allows to add signer name on the image (by default, LEFT)
	 */
	private SignerTextPosition signerTextPosition = SignerTextPosition.LEFT;

	/**
	 * This variable is define the image from text vertical alignment in connection
	 * with the image<br>
	 * <br>
	 * It has effect when the {@link SignerTextPosition SignerPosition} is
	 * {@link SignerTextPosition#LEFT LEFT} or {@link SignerTextPosition#RIGHT
	 * RIGHT}
	 */
	private SignerTextVerticalAlignment signerTextVerticalAlignment = SignerTextVerticalAlignment.MIDDLE;

	/**
	 * This variable set the more line text horizontal alignment
	 */
	private SignerTextHorizontalAlignment signerTextHorizontalAlignment = SignerTextHorizontalAlignment.LEFT;

	/**
	 * This variable defines the text to sign
	 */
	private String text;

	/**
	 * This variable defines the font to use
	 * (default is PTSerifRegular)
	 */
	private DSSFont dssFont;

	/**
	 * This variable defines a padding in pixels to bound text around
	 * (default is 5)
	 */
	private float padding = DEFAULT_PADDING;

	/**
	 * This variable defines the text color to use 
	 * (default is BLACK)
	 */
	private Color textColor = DEFAULT_TEXT_COLOR;

	/**
	 * This variable defines the background of a text bounding box
	 */
	private Color backgroundColor = DEFAULT_BACKGROUND_COLOR;

	/**
	 * Returns a signer text position respectively to an image
	 *
	 * @return {@link SignerTextPosition}
	 */
	public SignerTextPosition getSignerTextPosition() {
		return signerTextPosition;
	}

	/**
	 * Specifies a text position respectively to an image inside the signature field
	 * area
	 *
	 * @param signerTextPosition {@link SignerTextPosition} (TOP, BOTTOM, RIGHT,
	 *                           LEFT)
	 */
	public void setSignerTextPosition(SignerTextPosition signerTextPosition) {
		this.signerTextPosition = signerTextPosition;
	}

	/**
	 * Returns a signer text vertical alignment value
	 *
	 * @return {@link SignerTextVerticalAlignment}
	 */
	public SignerTextVerticalAlignment getSignerTextVerticalAlignment() {
		return signerTextVerticalAlignment;
	}

	/**
	 * Defines a vertical alignment (positioning) of signer text inside the
	 * signature field
	 *
	 * @param signerTextVerticalAlignment {@link SignerTextVerticalAlignment} (TOP,
	 *                                    MIDDLE, BOTTOM)
	 */
	public void setSignerTextVerticalAlignment(SignerTextVerticalAlignment signerTextVerticalAlignment) {
		this.signerTextVerticalAlignment = signerTextVerticalAlignment;
	}

	/**
	 * Returns a signer text horizontal alignment value
	 *
	 * @return {@link SignerTextHorizontalAlignment}
	 */
	public SignerTextHorizontalAlignment getSignerTextHorizontalAlignment() {
		return signerTextHorizontalAlignment;
	}

	/**
	 * Allows a horizontal alignment of a text with respect to its area
	 *
	 * @param signerTextHorizontalAlignment {@link SignerTextHorizontalAlignment}
	 *                                      (LEFT, CENTER, RIGHT)
	 */
	public void setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment signerTextHorizontalAlignment) {
		this.signerTextHorizontalAlignment = signerTextHorizontalAlignment;
	}

	/**
	 * Returns specified text font
	 * If not defined, returns a Default Font instance (PTSerifRegular)
	 *
	 * @return {@link DSSFont}
	 */
	public DSSFont getFont() {
		if (dssFont == null) {
			dssFont = DSSFileFont.initializeDefault();
		}
		return dssFont;
	}

	/**
	 * Sets a text font
	 *
	 * @param dssFont {@link DSSFont}
	 */
	public void setFont(DSSFont dssFont) {
		this.dssFont = dssFont;
	}

	/**
	 * Returns padding between text and its area
	 *
	 * @return {@code float} padding value
	 */
	public float getPadding() {
		return padding;
	}

	/**
	 * Sets a padding between text and its area
	 *
	 * @param padding {@code float} padding value
	 */
	public void setPadding(float padding) {
		this.padding = padding;
	}

	/**
	 * Returns text color parameter
	 *
	 * @return {@link Color}
	 */
	public Color getTextColor() {
		return textColor;
	}

	/**
	 * Sets color for the text
	 *
	 * @param textColor {@link Color} to set
	 */
	public void setTextColor(Color textColor) {
		this.textColor = textColor;
	}

	/**
	 * Returns background color for the text's area
	 *
	 * @return {@link Color} of the text area background
	 */
	public Color getBackgroundColor() {
		return backgroundColor;
	}

	/**
	 * Sets the provided background color for a test's area
	 *
	 * NOTE: use NULL for a transparent background (if supported by a selected implementation)
	 * DEFAULT: Color.WHITE 
	 *
	 * @param backgroundColor {@link Color} to set
	 */
	public void setBackgroundColor(Color backgroundColor) {
		this.backgroundColor = backgroundColor;
	}

	/**
	 * Returns defines text content
	 *
	 * @return {@link String} text
	 */
	public String getText() {
		return text;
	}

	/**
	 * Sets a text content parameter
	 *
	 * @param text {@link String} text to display
	 */
	public void setText(String text) {
		this.text = text;
	}

	/**
	 * Checks if the text property is set for the parameters
	 *
	 * @return TRUE if the text is defined, FALSE otherwise
	 */
	public boolean isEmpty() {
		return Utils.isStringEmpty(text);
	}

	@Override
	public String toString() {
		return "SignatureImageTextParameters [signerTextPosition=" + signerTextPosition
				+ ", signerTextVerticalAlignment=" + signerTextVerticalAlignment + ", signerTextHorizontalAlignment="
				+ signerTextHorizontalAlignment + ", text=" + text + ", padding=" + padding
				+ ", textColor=" + textColor + ", backgroundColor=" + backgroundColor + "]";
	}

}
