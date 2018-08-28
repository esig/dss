package eu.europa.esig.dss.pdf.pdfbox;

public class SignatureImageAndPosition {

    private float x;
    private float y;
	private byte[] signatureImage;

    public SignatureImageAndPosition() {
    }

    public SignatureImageAndPosition(float x, float y, byte[] signatureImage) {
        this.x = x;
        this.y = y;
        this.signatureImage = signatureImage;
    }

    public float getX() {
        return x;
    }

    public void setX(float x) {
        this.x = x;
    }

    public float getY() {
        return y;
    }

    public void setY(float y) {
        this.y = y;
    }

    public byte[] getSignatureImage() {
        return signatureImage;
    }

    public void setSignatureImage(byte[] signatureImage) {
        this.signatureImage = signatureImage;
    }
}
