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
package eu.europa.esig.dss.pades.signature.visible.defaultdrawer;

import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.pdfbox.visible.defaultdrawer.DefaultDrawerImageUtils;
import eu.europa.esig.dss.pdf.visible.CommonDrawerUtils;
import eu.europa.esig.dss.pdf.visible.ImageAndResolution;
import eu.europa.esig.dss.pdf.visible.ImageUtils;

import org.junit.Assert;
import org.junit.Test;

import javax.imageio.ImageIO;
import java.awt.Dimension;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;

public class ImageUtilsTest {

    @Test
    public void getOptimalSizeTest() throws IOException {
        SignatureImageParameters imageParameters = createSignatureImageParameters();

        Dimension optimalSizeDimension = ImageUtils.getOptimalSize(imageParameters);
        ImageAndResolution imageAndResolution = DefaultDrawerImageUtils.create(imageParameters);

        try (InputStream is = imageAndResolution.getInputStream()) {
            BufferedImage image = ImageIO.read(is);
            float ration = CommonDrawerUtils.getRation(imageParameters.getDpi());
            Assert.assertEquals((int)optimalSizeDimension.getWidth(), Math.round((float) image.getWidth() / ration));
            Assert.assertEquals((int)optimalSizeDimension.getHeight(), Math.round((float) image.getHeight() / ration));
            Assert.assertEquals((int)optimalSizeDimension.getWidth(), Math.round(imageAndResolution.toXPoint(image.getWidth())));
            Assert.assertEquals((int)optimalSizeDimension.getHeight(), Math.round(imageAndResolution.toYPoint(image.getHeight())));
        }
    }

    private SignatureImageParameters createSignatureImageParameters() {
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png")));
        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        textParameters.setText("My signature\nsecond line\nlong line is very long line with long text example this");
        imageParameters.setTextParameters(textParameters);

        return imageParameters;
    }
}
