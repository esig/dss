package eu.europa.esig.dss.pdf.pdfbox;

import eu.europa.esig.dss.pades.SignatureImageAndPosition;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.visible.ImageAndResolution;
import eu.europa.esig.dss.pades.signature.visible.ImageUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class SignatureImageAndPositionProcessor {

    private static final int ANGLE_360 = 360;
    private static final int ANGLE_90 = 90;
    private static final int ANGLE_180 = 180;
    private static final int ANGLE_270 = 270;

    public static final SignatureImageAndPosition process(final SignatureImageParameters signatureImageParameters, final PDDocument doc, final ImageAndResolution ires) throws IOException {
        SignatureImageParameters.VisualSignatureRotation visualSignatureRotation = signatureImageParameters.getRotation();
        if(visualSignatureRotation == null) {
            visualSignatureRotation = SignatureImageParameters.VisualSignatureRotation.NONE;
        }

        BufferedImage visualImageSignature = ImageIO.read(ires.getInputStream());
        float x = signatureImageParameters.getxAxis();
        float y = signatureImageParameters.getyAxis();

        if(visualSignatureRotation != null && !SignatureImageParameters.VisualSignatureRotation.NONE.equals(visualSignatureRotation)) {
            PDPage pdPage = doc.getPages().get(signatureImageParameters.getPage() - 1);

            int rotate = getRotation(visualSignatureRotation, pdPage);

            if(rotate != ANGLE_360) {
                visualImageSignature = ImageUtils.rotate(visualImageSignature, rotate);
            }

            switch (rotate) {
                case ANGLE_90:
                    x = pdPage.getMediaBox().getWidth() - ires.toXPoint(visualImageSignature.getWidth()) - signatureImageParameters.getyAxis();
                    y = signatureImageParameters.getxAxis();
                    break;
                case ANGLE_180:
                    x = pdPage.getMediaBox().getWidth() - ires.toXPoint(visualImageSignature.getWidth()) - signatureImageParameters.getxAxis();
                    y = pdPage.getMediaBox().getHeight() - ires.toYPoint(visualImageSignature.getHeight()) - signatureImageParameters.getyAxis();
                    break;
                case ANGLE_270:
                    x = signatureImageParameters.getyAxis();
                    y = pdPage.getMediaBox().getHeight() - ires.toYPoint(visualImageSignature.getHeight()) - signatureImageParameters.getxAxis();
                    break;
                case ANGLE_360:
                    //do nothing
                    break;
                default:
                    throw new IllegalStateException("rotation angle must be 90, 180, 270 or 360 (0)");
            }
        }

        ByteArrayOutputStream visualImageSignatureOutputStream = new ByteArrayOutputStream();
        String imageType = "jpg";
        if(visualImageSignature.getColorModel().hasAlpha()) {
            imageType = "png";
        }
        ImageIO.write(visualImageSignature, imageType, visualImageSignatureOutputStream);

        return new SignatureImageAndPosition(x, y, visualImageSignatureOutputStream.toByteArray());
    }

    private static int getRotation(SignatureImageParameters.VisualSignatureRotation visualSignatureRotation, PDPage pdPage) {
        int rotate = ANGLE_360;

        switch (visualSignatureRotation) {
            case AUTOMATIC:
                rotate = ANGLE_360 - pdPage.getRotation();
                break;
            case ROTATE_90:
                rotate = ANGLE_90;
                break;
            case ROTATE_180:
                rotate = ANGLE_180;
                break;
            case ROTATE_270:
                rotate = ANGLE_270;
                break;
            default:
                break;
        }

        return rotate;
    }
}
