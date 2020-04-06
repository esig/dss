package eu.europa.esig.dss.ws.signature.dto.parameters;

import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

@SuppressWarnings("serial")
public class RemoteSignatureImageTextParameters implements Serializable {

    private int[] backgroundColor;

    private RemoteDocument font;

    private Float padding;

    private String signerTextHorizontalAlignment;

    private String signerTextPosition;

    private String signerTextVerticalAlignment;

    private Integer size;

    private String text;

    private int[] textColor;

    public int[] getBackgroundColor() {
        return this.backgroundColor;
    }

    public void setBackgroundColor(final int[] backgroundColor) {
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

    public String getSignerTextHorizontalAlignment() {
        return this.signerTextHorizontalAlignment;
    }

    public void setSignerTextHorizontalAlignment(final String signerTextHorizontalAlignment) {
        this.signerTextHorizontalAlignment = signerTextHorizontalAlignment;
    }

    public String getSignerTextPosition() {
        return this.signerTextPosition;
    }

    public void setSignerTextPosition(final String signerTextPosition) {
        this.signerTextPosition = signerTextPosition;
    }

    public String getSignerTextVerticalAlignment() {
        return this.signerTextVerticalAlignment;
    }

    public void setSignerTextVerticalAlignment(final String signerTextVerticalAlignment) {
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

    public int[] getTextColor() {
        return this.textColor;
    }

    public void setTextColor(final int[] textColor) {
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
        return Arrays.equals(backgroundColor, that.backgroundColor) &&
                Objects.equals(font, that.font) &&
                Objects.equals(padding, that.padding) &&
                Objects.equals(signerTextHorizontalAlignment, that.signerTextHorizontalAlignment) &&
                Objects.equals(signerTextPosition, that.signerTextPosition) &&
                Objects.equals(signerTextVerticalAlignment, that.signerTextVerticalAlignment) &&
                Objects.equals(size, that.size) &&
                Objects.equals(text, that.text) &&
                Arrays.equals(textColor, that.textColor);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(font, padding, signerTextHorizontalAlignment, signerTextPosition, signerTextVerticalAlignment, size, text);
        result = 31 * result + Arrays.hashCode(backgroundColor);
        result = 31 * result + Arrays.hashCode(textColor);
        return result;
    }

    @Override
    public String toString() {
        return "RemoteSignatureImageTextParameters{" +
                "backgroundColor=" + Arrays.toString(backgroundColor) +
                ", font=" + font +
                ", padding=" + padding +
                ", signerTextHorizontalAlignment='" + signerTextHorizontalAlignment + '\'' +
                ", signerTextPosition='" + signerTextPosition + '\'' +
                ", signerTextVerticalAlignment='" + signerTextVerticalAlignment + '\'' +
                ", size=" + size +
                ", text='" + text + '\'' +
                ", textColor=" + Arrays.toString(textColor) +
                '}';
    }

}
