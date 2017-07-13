package eu.europa.esig.dss.pdf.pdfbox;

import eu.europa.esig.dss.pades.SignatureImageAndPosition;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.visible.ImageAndResolution;
import eu.europa.esig.dss.pades.signature.visible.ImageUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class SignatureImageAndPositionProcessor {

    private static final int ANGLE_360 = 360;
    private static final int ANGLE_90 = 90;
    private static final int ANGLE_180 = 180;
    private static final int ANGLE_270 = 270;

    private static final String SUPPORTED_ANGLES_ERROR_MESSAGE = "rotation angle must be 90, 180, 270 or 360 (0)";
    private static final String SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE = "not supported vertical alignment: ";
    private static final String SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE = "not supported horizontal alignment: ";

    public static final SignatureImageAndPosition process(final SignatureImageParameters signatureImageParameters, final PDDocument doc, final ImageAndResolution ires) throws IOException {
        BufferedImage visualImageSignature = ImageIO.read(ires.getInputStream());
        PDPage pdPage = doc.getPages().get(signatureImageParameters.getPage() - 1);

        int rotate = getRotation(signatureImageParameters.getRotation(), pdPage);
        if(rotate != ANGLE_360) {
            visualImageSignature = ImageUtils.rotate(visualImageSignature, rotate);
        }

        float x = processX(rotate, ires, visualImageSignature, pdPage, signatureImageParameters);
        float y = processY(rotate, ires, visualImageSignature, pdPage, signatureImageParameters);

        ByteArrayOutputStream visualImageSignatureOutputStream = new ByteArrayOutputStream();
        String imageType = "jpg";
        if(visualImageSignature.getColorModel().hasAlpha()) {
            imageType = "png";
        }
        ImageIO.write(visualImageSignature, imageType, visualImageSignatureOutputStream);

        return new SignatureImageAndPosition(x, y, visualImageSignatureOutputStream.toByteArray());
    }

    private static final float processX(int rotate, ImageAndResolution ires, BufferedImage visualImageSignature, PDPage pdPage, SignatureImageParameters signatureImageParameters) {
        float x = signatureImageParameters.getxAxis();

        SignatureImageParameters.VisualSignatureAlignmentHorizontal alignmentHorizontal = signatureImageParameters.getAlignmentHorizontal();
        if(alignmentHorizontal == null) {
            alignmentHorizontal = SignatureImageParameters.VisualSignatureAlignmentHorizontal.NONE;
        }
        SignatureImageParameters.VisualSignatureAlignmentVertical alignmentVertical = signatureImageParameters.getAlignmentVertical();
        if(alignmentVertical == null) {
            alignmentVertical = SignatureImageParameters.VisualSignatureAlignmentVertical.NONE;
        }

        PDRectangle mediaBox = pdPage.getMediaBox();

        switch (rotate) {
            case ANGLE_90:
                switch (alignmentVertical) {
                    case TOP:
                    case NONE:
                        x = mediaBox.getWidth() - ires.toXPoint(visualImageSignature.getWidth()) - signatureImageParameters.getyAxis();
                        break;
                    case MIDDLE:
                        x = (mediaBox.getWidth() - ires.toXPoint(visualImageSignature.getWidth())) / 2;
                        break;
                    case BOTTON:
                        x = signatureImageParameters.getyAxis();
                        break;
                    default:
                        throw new IllegalStateException(SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical.name());
                }
                break;
            case ANGLE_180:
                switch (alignmentHorizontal) {
                    case LEFT:
                    case NONE:
                        x = mediaBox.getWidth() - ires.toXPoint(visualImageSignature.getWidth()) - signatureImageParameters.getxAxis();
                        break;
                    case CENTER:
                        x = (mediaBox.getWidth() - ires.toXPoint(visualImageSignature.getWidth())) / 2;
                        break;
                    case RIGHT:
                        x = signatureImageParameters.getxAxis();
                        break;
                    default:
                        throw new IllegalStateException(SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal.name());
                }
                break;
            case ANGLE_270:
                switch (alignmentVertical) {
                    case TOP:
                    case NONE:
                        x = signatureImageParameters.getyAxis();
                        break;
                    case MIDDLE:
                        x = (mediaBox.getWidth() - ires.toXPoint(visualImageSignature.getWidth())) / 2;
                        break;
                    case BOTTON:
                        x = mediaBox.getWidth() - ires.toXPoint(visualImageSignature.getWidth()) - signatureImageParameters.getyAxis();
                        break;
                    default:
                        throw new IllegalStateException(SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical.name());
                }
                break;
            case ANGLE_360:
                switch (alignmentHorizontal) {
                    case LEFT:
                    case NONE:
                        //do nothing
                        break;
                    case CENTER:
                        x = (mediaBox.getWidth() - ires.toXPoint(visualImageSignature.getWidth())) / 2;
                        break;
                    case RIGHT:
                        x = mediaBox.getWidth() -ires.toXPoint(visualImageSignature.getWidth()) - signatureImageParameters.getxAxis();
                        break;
                    default:
                        throw new IllegalStateException(SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal.name());
                }
                break;
            default:
                throw new IllegalStateException(SUPPORTED_ANGLES_ERROR_MESSAGE);
        }

        return x;
    }

    private static final float processY(int rotate, ImageAndResolution ires, BufferedImage visualImageSignature, PDPage pdPage, SignatureImageParameters signatureImageParameters) {
        float y = signatureImageParameters.getyAxis();

        SignatureImageParameters.VisualSignatureAlignmentHorizontal alignmentHorizontal = signatureImageParameters.getAlignmentHorizontal();
        if(alignmentHorizontal == null) {
            alignmentHorizontal = SignatureImageParameters.VisualSignatureAlignmentHorizontal.NONE;
        }
        SignatureImageParameters.VisualSignatureAlignmentVertical alignmentVertical = signatureImageParameters.getAlignmentVertical();
        if(alignmentVertical == null) {
            alignmentVertical = SignatureImageParameters.VisualSignatureAlignmentVertical.NONE;
        }

        PDRectangle mediaBox = pdPage.getMediaBox();

        switch (rotate) {
            case ANGLE_90:
                switch (alignmentHorizontal) {
                    case LEFT:
                    case NONE:
                        y = signatureImageParameters.getxAxis();
                        break;
                    case CENTER:
                        y = (mediaBox.getHeight() - ires.toXPoint(visualImageSignature.getHeight())) / 2;
                        break;
                    case RIGHT:
                        y = mediaBox.getHeight() - ires.toYPoint(visualImageSignature.getHeight()) - signatureImageParameters.getxAxis();
                        break;
                    default:
                        throw new IllegalStateException(SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal.name());
                }
                break;
            case ANGLE_180:
                switch (alignmentVertical) {
                    case TOP:
                    case NONE:
                        y = mediaBox.getHeight() - ires.toYPoint(visualImageSignature.getHeight()) - signatureImageParameters.getyAxis();
                        break;
                    case MIDDLE:
                        y = (mediaBox.getHeight() - ires.toYPoint(visualImageSignature.getHeight())) / 2;
                        break;
                    case BOTTON:
                        //do nothing
                        break;
                    default:
                        throw new IllegalStateException(SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical.name());
                }
                break;
            case ANGLE_270:
                switch (alignmentHorizontal) {
                    case LEFT:
                    case NONE:
                        y = mediaBox.getHeight() - ires.toYPoint(visualImageSignature.getHeight()) - signatureImageParameters.getxAxis();
                        break;
                    case CENTER:
                        y = (mediaBox.getHeight() - ires.toXPoint(visualImageSignature.getHeight())) / 2;
                        break;
                    case RIGHT:
                        y = signatureImageParameters.getxAxis();
                        break;
                    default:
                        throw new IllegalStateException(SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal.name());
                }
                break;
            case ANGLE_360:
                switch (alignmentVertical) {
                    case TOP:
                    case NONE:
                        //do nothing
                        break;
                    case MIDDLE:
                        y = (mediaBox.getHeight() - ires.toYPoint(visualImageSignature.getHeight())) / 2;
                        break;
                    case BOTTON:
                        y = mediaBox.getHeight() - ires.toYPoint(visualImageSignature.getHeight()) - signatureImageParameters.getyAxis();
                        break;
                    default:
                        throw new IllegalStateException(SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical.name());
                }
                break;
            default:
                throw new IllegalStateException(SUPPORTED_ANGLES_ERROR_MESSAGE);
        }

        return y;
    }

    private static boolean needRotation(SignatureImageParameters.VisualSignatureRotation visualSignatureRotation) {
        return visualSignatureRotation != null && !SignatureImageParameters.VisualSignatureRotation.NONE.equals(visualSignatureRotation);
    }

    private static int getRotation(SignatureImageParameters.VisualSignatureRotation visualSignatureRotation, PDPage pdPage) {
        int rotate = ANGLE_360;

        if(needRotation(visualSignatureRotation)) {
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
                    throw new IllegalStateException(SUPPORTED_ANGLES_ERROR_MESSAGE);
            }
        }

        return rotate;
    }
}
