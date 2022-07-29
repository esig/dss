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
package eu.europa.esig.dss.ws.signature.dto.parameters;

import eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.enumerations.SignerTextVerticalAlignment;
import eu.europa.esig.dss.enumerations.TextWrapping;
import eu.europa.esig.dss.ws.dto.RemoteColor;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.io.Serializable;
import java.util.Objects;

/**
 * The signature parameters for text image creation
 *
 */
@SuppressWarnings("serial")
public class RemoteSignatureImageTextParameters implements Serializable {

    /** The text bounding box background color */
	private RemoteColor backgroundColor;

	/** The Font document file */
    private RemoteDocument font;

    /** Defines how the given text should be wrapped within the signature field's box */
    private TextWrapping textWrapping;

    /** The padding of the text boundary box */
    private Float padding;

    /** The horizontal alignment of the text */
	private SignerTextHorizontalAlignment signerTextHorizontalAlignment;

    /** The vertical alignment of the text */
    private SignerTextVerticalAlignment signerTextVerticalAlignment;

    /** The text position relatively to the image (if present) */
	private SignerTextPosition signerTextPosition;

	/** The text size */
    private Integer size;

    /** The text string */
    private String text;

    /** The text color */
	private RemoteColor textColor;

    /**
     * Default constructor instantiating object with null values
     */
    public RemoteSignatureImageTextParameters() {
    }

    /**
     * Gets the background color of text bounding box
     *
     * @return {@link RemoteColor}
     */
	public RemoteColor getBackgroundColor() {
        return this.backgroundColor;
    }

    /**
     * Sets the background color of text bounding box
     *
     * @param backgroundColor {@link RemoteColor}
     */
	public void setBackgroundColor(final RemoteColor backgroundColor) {
        this.backgroundColor = backgroundColor;
    }

    /**
     * Gets the font document
     *
     * @return {@link RemoteDocument}
     */
    public RemoteDocument getFont() {
        return this.font;
    }

    /**
     * Sets the font document
     *
     * @param font {@link RemoteDocument}
     */
    public void setFont(final RemoteDocument font) {
        this.font = font;
    }

    /**
     * Gets the text wrapping
     *
     * @return {@link TextWrapping}
     */
    public TextWrapping getTextWrapping() {
        return textWrapping;
    }

    /**
     * Sets the text wrapping, defining a way the text will be generated
     *
     * @param textWrapping {@link TextWrapping}
     */
    public void setTextWrapping(TextWrapping textWrapping) {
        this.textWrapping = textWrapping;
    }

    /**
     * Gets text bounding box padding
     *
     * @return {@link Float}
     */
    public Float getPadding() {
        return this.padding;
    }

    /**
     * Sets text bounding box padding
     *
     * @param padding {@link Float}
     */
    public void setPadding(final Float padding) {
        this.padding = padding;
    }

    /**
     * Gets text horizontal alignment
     *
     * @return {@link SignerTextHorizontalAlignment}
     */
	public SignerTextHorizontalAlignment getSignerTextHorizontalAlignment() {
        return this.signerTextHorizontalAlignment;
    }

    /**
     * Sets text horizontal alignment
     *
     * @param signerTextHorizontalAlignment {@link SignerTextHorizontalAlignment}
     */
	public void setSignerTextHorizontalAlignment(final SignerTextHorizontalAlignment signerTextHorizontalAlignment) {
        this.signerTextHorizontalAlignment = signerTextHorizontalAlignment;
    }

    /**
     * Gets text vertical alignment
     *
     * @return {@link SignerTextHorizontalAlignment}
     */
    public SignerTextVerticalAlignment getSignerTextVerticalAlignment() {
        return this.signerTextVerticalAlignment;
    }

    /**
     * Sets text vertical alignment
     *
     * @param signerTextVerticalAlignment {@link SignerTextVerticalAlignment}
     */
    public void setSignerTextVerticalAlignment(final SignerTextVerticalAlignment signerTextVerticalAlignment) {
        this.signerTextVerticalAlignment = signerTextVerticalAlignment;
    }

    /**
     * Gets SingerText position relatively to an image
     *
     * @return {@link SignerTextPosition}
     */
	public SignerTextPosition getSignerTextPosition() {
        return this.signerTextPosition;
    }

    /**
     * Sets SingerText position relatively to an image
     *
     * @param signerTextPosition {@link SignerTextPosition}
     */
	public void setSignerTextPosition(final SignerTextPosition signerTextPosition) {
        this.signerTextPosition = signerTextPosition;
    }

    /**
     * Gets the font size
     *
     * @return {@link Integer}
     */
    public Integer getSize() {
        return this.size;
    }

    /**
     * Sets the font size
     *
     * @param size {@link Integer}
     */
    public void setSize(final Integer size) {
        this.size = size;
    }

    /**
     * Gets the text string
     *
     * @return {@link String}
     */
    public String getText() {
        return this.text;
    }

    /**
     * Sets the text string
     *
     * @param text {@link String}
     */
    public void setText(final String text) {
        this.text = text;
    }

    /**
     * Gets the text color
     *
     * @return {@link RemoteColor}
     */
	public RemoteColor getTextColor() {
        return this.textColor;
    }

    /**
     * Sets the text color
     *
     * @param textColor {@link RemoteColor}
     */
	public void setTextColor(final RemoteColor textColor) {
        this.textColor = textColor;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final RemoteSignatureImageTextParameters that = (RemoteSignatureImageTextParameters) o;
		return Objects.equals(backgroundColor, that.backgroundColor) &&
                Objects.equals(font, that.font) &&
                Objects.equals(padding, that.padding) &&
                Objects.equals(signerTextHorizontalAlignment, that.signerTextHorizontalAlignment) &&
                Objects.equals(signerTextPosition, that.signerTextPosition) &&
                Objects.equals(signerTextVerticalAlignment, that.signerTextVerticalAlignment) &&
                Objects.equals(size, that.size) &&
                Objects.equals(text, that.text) &&
				Objects.equals(textColor, that.textColor);
    }

    @Override
    public int hashCode() {
		return Objects.hash(backgroundColor, font, padding, signerTextHorizontalAlignment, signerTextPosition, signerTextVerticalAlignment, size, text,
				textColor);
    }

    @Override
    public String toString() {
        return "RemoteSignatureImageTextParameters{" +
				"backgroundColor=" + backgroundColor +
                ", font=" + font +
                ", padding=" + padding +
                ", signerTextHorizontalAlignment='" + signerTextHorizontalAlignment + '\'' +
                ", signerTextPosition='" + signerTextPosition + '\'' +
                ", signerTextVerticalAlignment='" + signerTextVerticalAlignment + '\'' +
                ", size=" + size +
                ", text='" + text + '\'' +
				", textColor=" + textColor +
                '}';
    }

}
