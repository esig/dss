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

import eu.europa.esig.dss.pades.signature.visible.ImageFactory;
import java.awt.Dimension;
import java.io.File;
import java.io.IOException;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;

/**
 * Parameters for a visible signature creation
 *
 */
public class SignatureImageParameters {

    public static final int DEFAULT_PAGE = 1;

    /**
     * This variable contains the image to use (company logo,...)
     */
    private File image;

    /**
     * This variable defines the page where the image will appear (1st page by
     * default)
     */
    private int page = DEFAULT_PAGE;

    /**
     * This variable defines the position of the image in the PDF page (X axis)
     */
    private float xAxis = 0;

    /**
     * This variable defines the position of the image in the PDF page (Y axis)
     */
    private float yAxis = 0;

    /**
     * This variable is use to defines the text to generate on the image
     */
    private SignatureImageTextParameters textParameters;
    /**
     * Use to set visible signature Rectangle dimension
     */
    private Dimension dimension = null;
    /**
     * Use to get rectangle position from margins, axis values has priority over
     * margins
     */
    private float marginTop = 0;
    private float marginLeft = 0;
    private float marginRight = 0;
    private float marginBottom = 0;

    public File getImage() {
        return image;
    }

    public void setImage(File image) {
        this.image = image;
    }

    public float getxAxis() {
        return xAxis;
    }

    public void recalculateAxis(PDVisibleSignDesigner visibleSig) throws IOException {
        Dimension optimalSize = ImageFactory.getOptimalSize(this);
        if (dimension != null) {
            optimalSize = dimension;
        }
        if (marginTop > 0 && marginBottom == 0) {
            this.yAxis = this.marginTop;
        }
        if (marginLeft > 0 && marginRight == 0) {
            this.xAxis = marginLeft;
        }
        if (marginBottom > 0) {
            this.yAxis = visibleSig.getPageHeight() - optimalSize.height - marginBottom;
        }
        if (marginRight > 0) {
            this.xAxis = visibleSig.getPageWidth() - optimalSize.width - marginRight;
        }
    }

    public void setxAxis(float xAxis) {
        this.xAxis = xAxis;
    }

    public float getyAxis() {
        return yAxis;
    }

    public void setyAxis(float yAxis) {
        this.yAxis = yAxis;
    }

    public void setDimension(Dimension dimension) {
        this.dimension = dimension;
    }

    public Dimension getDimension() {
        return this.dimension;
    }

    public int getPage() {
        return page;
    }

    public void setPage(int page) {
        this.page = page;
    }

    public SignatureImageTextParameters getTextParameters() {
        return textParameters;
    }

    public void setTextParameters(SignatureImageTextParameters textParameters) {
        this.textParameters = textParameters;
    }

    /**
     * @return the marginTop
     */
    public float getMarginTop() {
        return marginTop;
    }

    /**
     * @param marginTop the marginTop to set
     */
    public void setMarginTop(float marginTop) {
        this.marginTop = marginTop;
    }

    /**
     * @return the marginLeft
     */
    public float getMarginLeft() {
        return marginLeft;
    }

    /**
     * @param marginLeft the marginLeft to set
     */
    public void setMarginLeft(float marginLeft) {
        this.marginLeft = marginLeft;
    }

    /**
     * @return the marginRight
     */
    public float getMarginRight() {
        return marginRight;
    }

    /**
     * @param marginRight the marginRight to set
     */
    public void setMarginRight(float marginRight) {
        this.marginRight = marginRight;
    }

    /**
     * @return the marginBottom
     */
    public float getMarginBottom() {
        return marginBottom;
    }

    /**
     * @param marginBottom the marginBottom to set
     */
    public void setMarginBottom(float marginBottom) {
        this.marginBottom = marginBottom;
    }

}
