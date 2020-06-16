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

import java.io.Serializable;
import java.util.Objects;

import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.ws.dto.RemoteColor;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

@SuppressWarnings("serial")
public class RemoteSignatureImageParameters implements Serializable {

	private VisualSignatureAlignmentHorizontal alignmentHorizontal;

	private VisualSignatureAlignmentVertical alignmentVertical;

	private RemoteColor backgroundColor;

    private Integer dpi;

    private Integer height;

    private RemoteDocument image;

    private Integer page;

	private VisualSignatureRotation rotation;

    private RemoteSignatureImageTextParameters textParameters;

    private Integer width;

    private Float xAxis;

    private Float yAxis;

    private Integer zoom;

	public VisualSignatureAlignmentHorizontal getAlignmentHorizontal() {
        return this.alignmentHorizontal;
    }

	public void setAlignmentHorizontal(final VisualSignatureAlignmentHorizontal alignmentHorizontal) {
        this.alignmentHorizontal = alignmentHorizontal;
    }

	public VisualSignatureAlignmentVertical getAlignmentVertical() {
        return this.alignmentVertical;
    }

	public void setAlignmentVertical(final VisualSignatureAlignmentVertical alignmentVertical) {
        this.alignmentVertical = alignmentVertical;
    }

	public RemoteColor getBackgroundColor() {
        return this.backgroundColor;
    }

	public void setBackgroundColor(final RemoteColor backgroundColor) {
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

	public VisualSignatureRotation getRotation() {
        return this.rotation;
    }

	public void setRotation(final VisualSignatureRotation rotation) {
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
				Objects.equals(backgroundColor, that.backgroundColor) &&
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
		return Objects.hash(alignmentHorizontal, alignmentVertical, dpi, height, image, page, rotation, textParameters, width, xAxis, yAxis, zoom,
				backgroundColor);
    }

    @Override
    public String toString() {
        return "RemoteSignatureImageParameters{" +
                "alignmentHorizontal='" + alignmentHorizontal + '\'' +
                ", alignmentVertical='" + alignmentVertical + '\'' +
				", backgroundColor=" + backgroundColor
				+
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
