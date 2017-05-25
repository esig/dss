package eu.europa.esig.dss.pades.signature.visible;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import org.junit.Assert;
import org.junit.Test;

import javax.imageio.ImageIO;
import java.awt.Color;
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

        Assert.assertEquals((long)optimalSizeDimension.getWidth(), (long) image.getWidth());
        Assert.assertEquals((long)optimalSizeDimension.getHeight(), (long) image.getHeight());
    }

    private SignatureImageParameters createSignatureImageParameters() {
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setImage(new FileDocument(new File("src/test/resources/small-red.jpg")));
        imageParameters.setxAxis(200);
        imageParameters.setyAxis(300);
        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        textParameters.setText("My signature\nsecond line\nlong line is very long line with long text example this");
        textParameters.setTextColor(Color.BLUE);
        textParameters.setSignerNamePosition(SignatureImageTextParameters.SignerPosition.LEFT);
        imageParameters.setTextParameters(textParameters);

        return imageParameters;
    }
}
