package eu.europa.esig.dss.pades.signature.visible;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import org.junit.Assert;
import org.junit.Test;

import javax.imageio.ImageIO;
import java.awt.Dimension;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

public class ImageUtilsTest {

    @Test
    public void getOptimalSizeTest() throws IOException {
        SignatureImageParameters imageParameters = createSignatureImageParameters();

        Dimension optimalSizeDimension = ImageUtils.getOptimalSize(imageParameters);
        ImageAndResolution imageAndResolution = ImageUtils.create(imageParameters);

        BufferedImage image = ImageIO.read(imageAndResolution.getInputStream());

        float ration = ImageUtils.getDpi(imageParameters.getDpi())/(float) ImageTextWriter.PDF_DEFAULT_DPI;

        Assert.assertEquals((int)optimalSizeDimension.getWidth(), Math.round((float) image.getWidth() / ration));
        Assert.assertEquals((int)optimalSizeDimension.getHeight(), Math.round((float) image.getHeight() / ration));
        Assert.assertEquals((int)optimalSizeDimension.getWidth(), Math.round(imageAndResolution.toXPoint(image.getWidth())));
        Assert.assertEquals((int)optimalSizeDimension.getHeight(), Math.round(imageAndResolution.toYPoint(image.getHeight())));
    }

    private SignatureImageParameters createSignatureImageParameters() {
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setImage(new FileDocument(new File("src/test/resources/signature-image.png")));
        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        textParameters.setText("My signature\nsecond line\nlong line is very long line with long text example this");
        imageParameters.setTextParameters(textParameters);

        return imageParameters;
    }
}
