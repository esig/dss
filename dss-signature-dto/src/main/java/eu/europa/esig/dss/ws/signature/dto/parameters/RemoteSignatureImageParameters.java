package eu.europa.esig.dss.ws.signature.dto.parameters;

import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

@SuppressWarnings("serial")
public class RemoteSignatureImageParameters implements Serializable {

    private String alignmentHorizontal;

    private String alignmentVertical;

    private int[] backgroundColor;

    private Integer dpi;

    private Integer height;

    private RemoteDocument image;

    private Integer page;

    private String rotation;

    private RemoteSignatureImageTextParameters textParameters;

    private Integer width;

    private Float xAxis;

    private Float yAxis;

    private Integer zoom;

    public String getAlignmentHorizontal() {
        return this.alignmentHorizontal;
    }

    public void setAlignmentHorizontal(final String alignmentHorizontal) {
        this.alignmentHorizontal = alignmentHorizontal;
    }

    public String getAlignmentVertical() {
        return this.alignmentVertical;
    }

    public void setAlignmentVertical(final String alignmentVertical) {
        this.alignmentVertical = alignmentVertical;
    }

    public int[] getBackgroundColor() {
        return this.backgroundColor;
    }

    public void setBackgroundColor(final int[] backgroundColor) {
        this.backgroundColor = backgroundColor;
    }

    public Integer getDpi() {
        return this.dpi;
    }

    public void setDpi(final Integer dpi) {
        this.dpi = dpi;
    }

    public Integer getHeight() {
        return this.height;
    }

    public void setHeight(final Integer height) {
        this.height = height;
    }

    public RemoteDocument getImage() {
        return this.image;
    }

    public void setImage(final RemoteDocument image) {
        this.image = image;
    }

    public RemoteSignatureImageTextParameters getTextParameters() {
        return this.textParameters;
    }

    public void setTextParameters(final RemoteSignatureImageTextParameters textParameters) {
        this.textParameters = textParameters;
    }

    public Integer getPage() {
        return this.page;
    }

    public void setPage(final Integer page) {
        this.page = page;
    }

    public String getRotation() {
        return this.rotation;
    }

    public void setRotation(final String rotation) {
        this.rotation = rotation;
    }

    public Integer getWidth() {
        return this.width;
    }

    public void setWidth(final Integer width) {
        this.width = width;
    }

    public Float getxAxis() {
        return this.xAxis;
    }

    public void setxAxis(final Float xAxis) {
        this.xAxis = xAxis;
    }

    public Float getyAxis() {
        return this.yAxis;
    }

    public void setyAxis(final Float yAxis) {
        this.yAxis = yAxis;
    }

    public Integer getZoom() {
        return this.zoom;
    }

    public void setZoom(final Integer zoom) {
        this.zoom = zoom;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final RemoteSignatureImageParameters that = (RemoteSignatureImageParameters) o;
        return Objects.equals(alignmentHorizontal, that.alignmentHorizontal) &&
                Objects.equals(alignmentVertical, that.alignmentVertical) &&
                Arrays.equals(backgroundColor, that.backgroundColor) &&
                Objects.equals(dpi, that.dpi) &&
                Objects.equals(height, that.height) &&
                Objects.equals(image, that.image) &&
                Objects.equals(page, that.page) &&
                Objects.equals(rotation, that.rotation) &&
                Objects.equals(textParameters, that.textParameters) &&
                Objects.equals(width, that.width) &&
                Objects.equals(xAxis, that.xAxis) &&
                Objects.equals(yAxis, that.yAxis) &&
                Objects.equals(zoom, that.zoom);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(alignmentHorizontal, alignmentVertical, dpi, height, image, page, rotation, textParameters, width, xAxis, yAxis, zoom);
        result = 31 * result + Arrays.hashCode(backgroundColor);
        return result;
    }

    @Override
    public String toString() {
        return "RemoteSignatureImageParameters{" +
                "alignmentHorizontal='" + alignmentHorizontal + '\'' +
                ", alignmentVertical='" + alignmentVertical + '\'' +
                ", backgroundColor=" + Arrays.toString(backgroundColor) +
                ", dpi=" + dpi +
                ", height=" + height +
                ", image=" + image +
                ", page=" + page +
                ", rotation='" + rotation + '\'' +
                ", textParameters=" + textParameters +
                ", width=" + width +
                ", xAxis=" + xAxis +
                ", yAxis=" + yAxis +
                ", zoom=" + zoom +
                '}';
    }

}
