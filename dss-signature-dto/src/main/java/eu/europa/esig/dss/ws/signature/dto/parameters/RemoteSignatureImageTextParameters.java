package eu.europa.esig.dss.ws.signature.dto.parameters;

import java.io.Serializable;
import java.util.Objects;

import eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.enumerations.SignerTextVerticalAlignment;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

@SuppressWarnings("serial")
public class RemoteSignatureImageTextParameters implements Serializable {

	private RemoteColor backgroundColor;

    private RemoteDocument font;

    private Float padding;

	private SignerTextHorizontalAlignment signerTextHorizontalAlignment;

	private SignerTextPosition signerTextPosition;

	private SignerTextVerticalAlignment signerTextVerticalAlignment;

    private Integer size;

    private String text;

	private RemoteColor textColor;

	public RemoteColor getBackgroundColor() {
        return this.backgroundColor;
    }

	public void setBackgroundColor(final RemoteColor backgroundColor) {
        this.backgroundColor = backgroundColor;
    }

    public RemoteDocument getFont() {
        return this.font;
    }

    public void setFont(final RemoteDocument font) {
        this.font = font;
    }

    public Float getPadding() {
        return this.padding;
    }

    public void setPadding(final Float padding) {
        this.padding = padding;
    }

	public SignerTextHorizontalAlignment getSignerTextHorizontalAlignment() {
        return this.signerTextHorizontalAlignment;
    }

	public void setSignerTextHorizontalAlignment(final SignerTextHorizontalAlignment signerTextHorizontalAlignment) {
        this.signerTextHorizontalAlignment = signerTextHorizontalAlignment;
    }

	public SignerTextPosition getSignerTextPosition() {
        return this.signerTextPosition;
    }

	public void setSignerTextPosition(final SignerTextPosition signerTextPosition) {
        this.signerTextPosition = signerTextPosition;
    }

	public SignerTextVerticalAlignment getSignerTextVerticalAlignment() {
        return this.signerTextVerticalAlignment;
    }

	public void setSignerTextVerticalAlignment(final SignerTextVerticalAlignment signerTextVerticalAlignment) {
        this.signerTextVerticalAlignment = signerTextVerticalAlignment;
    }

    public Integer getSize() {
        return this.size;
    }

    public void setSize(final Integer size) {
        this.size = size;
    }

    public String getText() {
        return this.text;
    }

    public void setText(final String text) {
        this.text = text;
    }

	public RemoteColor getTextColor() {
        return this.textColor;
    }

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
