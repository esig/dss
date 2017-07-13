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
package eu.europa.esig.dss.pades.signature;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.TestUtils;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPageTree;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.awt.Color;
import java.awt.Font;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class PAdESVisibleSignaturePositionTest {

	private static final Color TRANSPARENT = new Color(0, 0, 0, 0.25f);
	private static final int DPI = 144;

	/**
	 * The degree of similarity between generated and original image
	 */
	private static final float SIMILARITY_LIMIT = 0.99f;
	/**
	 * Comparison resolution: step in pixels in horizontal and vertical directions.
	 */
	private static final int CHECK_RESOLUTION = 1;

    private DocumentSignatureService<PAdESSignatureParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private MockPrivateKeyEntry privateKeyEntry;
    private DSSDocument signitureImage;
    /**
     * PDF-s rotated by pdftk on Ubuntu (<a href="https://packages.ubuntu.com/search?keywords=pdftk">pdftk Ubuntu packages</a>)<br>
     * Tool site: <a href="https://www.pdflabs.com/tools/pdftk-the-pdf-toolkit/">pdftk</a>
     */
    private Map<String, DSSDocument> signablePdfs = new HashMap<>();

    @Before
    public void init() throws Exception {
        CertificateService certificateService = new CertificateService();
        privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

        certificateService = new CertificateService();
        privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
        signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        service = new PAdESService(certificateVerifier);

        signitureImage = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/signature.png"));

        signablePdfs.put("normal", new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test.pdf")));
        signablePdfs.put("90", new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_90.pdf")));
        signablePdfs.put("180", new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_180.pdf")));
        signablePdfs.put("270", new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_270.pdf")));
        signablePdfs.put("-90", new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_-90.pdf")));
        signablePdfs.put("-180", new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_-180.pdf")));
        signablePdfs.put("-270", new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_-270.pdf")));
        signablePdfs.put("minoltaScan", new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/sun.pdf"))); //scanner type from pdf
        signablePdfs.put("minoltaScan90", new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/sun_90.pdf"))); //scanner type from pdf
    }

    @Test
    public void pdfRotateDegreeTest() throws IOException {
        checkRotation(signablePdfs.get("normal").openStream(), 0);
        checkRotation(signablePdfs.get("90").openStream(), 90);
        checkRotation(signablePdfs.get("180").openStream(), 180);
        checkRotation(signablePdfs.get("270").openStream(), 270);
        checkRotation(signablePdfs.get("-90").openStream(), 270);
        checkRotation(signablePdfs.get("-180").openStream(), 180);
        checkRotation(signablePdfs.get("-270").openStream(), 90);
    }

    @Test
    public void doTest() throws Exception {
        SignatureImageParameters signatureImageParameters = createSignatureImageParameters();

        signatureImageParameters.setRotation(SignatureImageParameters.VisualSignatureRotation.NONE); //default
        checkImageSimilarityPdf("normal", "check_custom_10_20.pdf");
        checkImageSimilarityPdf("90", "check_custom_rotate_none_90_10_20.pdf");
        checkImageSimilarityPdf("180", "check_custom_rotate_none_180_10_20.pdf");
        checkImageSimilarityPdf("270", "check_custom_rotate_none_270_10_20.pdf");
        checkImageSimilarityPdf("-270", "check_custom_rotate_none_90_10_20.pdf");
        checkImageSimilarityPdf("-180", "check_custom_rotate_none_180_10_20.pdf");
        checkImageSimilarityPdf("-90", "check_custom_rotate_none_270_10_20.pdf");
        signatureImageParameters.setRotation(SignatureImageParameters.VisualSignatureRotation.AUTOMATIC);
        checkImageSimilarityPdf("normal", "check_custom_10_20.pdf");
        checkImageSimilarityPdf("90", "check_custom_rotate_automatic_90_10_20.pdf");
        checkImageSimilarityPdf("180", "check_custom_rotate_automatic_180_10_20.pdf");
        checkImageSimilarityPdf("270", "check_custom_rotate_automatic_270_10_20.pdf");
        checkImageSimilarityPdf("-270", "check_custom_rotate_automatic_90_10_20.pdf");
        checkImageSimilarityPdf("-180", "check_custom_rotate_automatic_180_10_20.pdf");
        checkImageSimilarityPdf("-90", "check_custom_rotate_automatic_270_10_20.pdf");
        signatureImageParameters.setRotation(SignatureImageParameters.VisualSignatureRotation.ROTATE_270);
        checkImageSimilarityPdf("normal", "check_custom_rotate270_10_20.pdf");
        checkImageSimilarityPdf("90", "check_custom_rotate270_90_10_20.pdf");
        checkImageSimilarityPdf("180", "check_custom_rotate270_180_10_20.pdf");
        checkImageSimilarityPdf("270", "check_custom_rotate270_270_10_20.pdf");
        checkImageSimilarityPdf("-270", "check_custom_rotate270_90_10_20.pdf");
        checkImageSimilarityPdf("-180", "check_custom_rotate270_180_10_20.pdf");
        checkImageSimilarityPdf("-90", "check_custom_rotate270_270_10_20.pdf");
        signatureImageParameters.setRotation(SignatureImageParameters.VisualSignatureRotation.ROTATE_180);
        checkImageSimilarityPdf("normal", "check_custom_rotate180_10_20.pdf");
        signatureImageParameters.setRotation(SignatureImageParameters.VisualSignatureRotation.ROTATE_90);
        checkImageSimilarityPdf("normal", "check_custom_rotate90_10_20.pdf");

        //check minolta scanner
        signatureImageParameters.setRotation(SignatureImageParameters.VisualSignatureRotation.AUTOMATIC);
        checkImageSimilarityPdf("minoltaScan", "check_sun.pdf");
        /**
         * sun.pdf and sun90.pdf not equal, when convert it to image (two scanning and the scanner can not scan equal twice).
         * So we need the similarity of the sun.pdf and sun90.pdf.
         * After the signing the visual signature does not have to change the similarity.
         */
        float sunSimilarity = checkImageSimilarity(pdfToBufferedImage(
                signablePdfs.get("minoltaScan").openStream()),
                pdfToBufferedImage(signablePdfs.get("minoltaScan90").openStream()),
                CHECK_RESOLUTION);
        checkImageSimilarityPdf("minoltaScan90", "check_sun.pdf", sunSimilarity);
    }

    @Test
    @Ignore("for generation and manual testing")
    public void rotateTest() throws Exception {
        SignatureImageParameters signatureImageParameters = createSignatureImageParameters();

        signatureImageParameters.setRotation(SignatureImageParameters.VisualSignatureRotation.AUTOMATIC);
        signatureImageParameters.setAlignmentHorizontal(SignatureImageParameters.VisualSignatureAlignmentHorizontal.LEFT);
        signatureImageParameters.setAlignmentVertical(SignatureImageParameters.VisualSignatureAlignmentVertical.MIDDLE);
        DSSDocument document = sign(signablePdfs.get("270"));
        File checkPdfFile = new File("target/pdf/check.pdf");
        checkPdfFile.getParentFile().mkdirs();
        IOUtils.copy(document.openStream(), new FileOutputStream(checkPdfFile));
    }

    @Test
    @Ignore("for generation and manual testing")
    public void bigGeneratorTest() throws Exception {
        SignatureImageParameters signatureImageParameters = createSignatureImageParameters();

        for(SignatureImageParameters.VisualSignatureRotation rotation : SignatureImageParameters.VisualSignatureRotation.values()) {
            for (SignatureImageParameters.VisualSignatureAlignmentHorizontal horizontal : SignatureImageParameters.VisualSignatureAlignmentHorizontal.values()) {
                for (SignatureImageParameters.VisualSignatureAlignmentVertical vertical : SignatureImageParameters.VisualSignatureAlignmentVertical.values()) {
                    signatureImageParameters.setRotation(rotation);
                    signatureImageParameters.setAlignmentHorizontal(horizontal);
                    signatureImageParameters.setAlignmentVertical(vertical);
                    String[] pdfs = new String[]{"normal", "90", "180", "270"};
                    for (String pdf : pdfs) {
                        DSSDocument document = sign(signablePdfs.get(pdf));
                        File checkPdfFile = new File("target/pdf/check_" + rotation.name() + "_" + pdf + "_" + horizontal.name() + "_" + vertical.name() + ".pdf");
                        checkPdfFile.getParentFile().mkdirs();
                        IOUtils.copy(document.openStream(), new FileOutputStream(checkPdfFile));
                    }
                }
            }
        }
    }

    private DSSDocument sign(DSSDocument document) {
        ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
        SignatureValue signatureValue = TestUtils.sign(SignatureAlgorithm.RSA_SHA256, privateKeyEntry, dataToSign);
        return service.signDocument(document, signatureParameters, signatureValue);
    }

    private void checkRotation(InputStream inputStream, int rotate) throws IOException {
        PDDocument document = PDDocument.load(inputStream);

        Assert.assertEquals(rotate, document.getPages().get(0).getRotation());
    }

    private void checkImageSimilarityPdf(String samplePdf, String checkPdf, float similarity) throws IOException {
        DSSDocument document = sign(signablePdfs.get(samplePdf));
        PDDocument sampleDocument = PDDocument.load(document.openStream());
        PDDocument checkDocument = PDDocument.load(getClass().getResourceAsStream("/visualSignature/check/" + checkPdf));

        PDPageTree samplePageTree = sampleDocument.getPages();
        PDPageTree checkPageTree = checkDocument.getPages();

        Assert.assertEquals(checkPageTree.getCount(), samplePageTree.getCount());

        PDFRenderer sampleRenderer = new PDFRenderer(sampleDocument);
        PDFRenderer checkRenderer = new PDFRenderer(checkDocument);

        for(int pageNumber = 0; pageNumber < checkPageTree.getCount(); pageNumber++) {
            BufferedImage sampleImage = sampleRenderer.renderImageWithDPI(pageNumber, DPI);
            BufferedImage checkImage = checkRenderer.renderImageWithDPI(pageNumber, DPI);

            float checkSimilarity = checkImageSimilarity(sampleImage, checkImage, CHECK_RESOLUTION);
            float calculatedSimilarity = (float)((int)( similarity *100f))/100f; //calulate rotated position has about 1 pixel position difference
            Assert.assertTrue(checkSimilarity >= calculatedSimilarity);
        }
    }

    private void checkImageSimilarityPdf(String samplePdf, String checkPdf) throws IOException {
        checkImageSimilarityPdf(samplePdf, checkPdf, SIMILARITY_LIMIT);
    }

	private float checkImageSimilarity(BufferedImage sampleImage, BufferedImage checkImage, int resolution) {
		try {
			int width = sampleImage.getWidth();
			int height = sampleImage.getHeight();
			int checkWidth = checkImage.getWidth();
			int checkHeight = checkImage.getHeight();
			if (width == 0 || height == 0 || checkWidth == 0 || checkHeight == 0) {
			    Assert.fail(String.format("invalid image size: sample(%dx%d) vs check(%dx%d)", width, height, checkWidth, checkHeight));
			}
			if (width != checkWidth || height != checkHeight) {
			    Assert.fail(String.format("images size not equal: sample(%dx%d) vs check(%dx%d)", width, height, checkWidth, checkHeight));
			}

			int matchingPixels = 0;
			int checkedPixels = 0;
			for (int y = 0; y < height; y += resolution) {
				for (int x = 0; x < width; x += resolution) {
					int sampleRGB = sampleImage.getRGB(x, y);
					int checkRGB = checkImage.getRGB(x, y);

					if (sampleRGB == checkRGB) {
						matchingPixels++;
					} else {
					    checkImage.setRGB(x, y, Color.RED.getRGB());
                    }

					checkedPixels++;
				}
			}

			return (float) matchingPixels / checkedPixels;
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

    private SignatureImageParameters createSignatureImageParameters() throws Exception {
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setImage(signitureImage);
        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        textParameters.setText("My signature\nsecond line\nlong line is very long line with long text example this");
        textParameters.setSignerNamePosition(SignatureImageTextParameters.SignerPosition.LEFT);
        textParameters.setBackgroundColor(TRANSPARENT);
        textParameters.setTextColor(Color.MAGENTA);
        textParameters.setFont(new Font("Arial", Font.BOLD, 8));
        imageParameters.setTextParameters(textParameters);

        imageParameters.setBackgroundColor(TRANSPARENT);
        imageParameters.setxAxis(10);
        imageParameters.setyAxis(20);

        signatureParameters.bLevel().setSigningDate(new Date());

        signatureParameters.setSignatureImageParameters(imageParameters);

        return imageParameters;
    }

    private BufferedImage pdfToBufferedImage(InputStream inputStream) throws IOException {
        PDDocument document = PDDocument.load(inputStream);
        PDFRenderer renderer = new PDFRenderer(document);
        return renderer.renderImageWithDPI(0, DPI);
    }
}
