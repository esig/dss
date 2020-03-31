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
package eu.europa.esig.dss.pades.signature.visible;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PdfScreenshotUtils;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.pades.SignatureImageParameters.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;

@Tag("slow")
public class PAdESVisibleSignaturePositionTest extends PKIFactoryAccess {

	private static final Color TRANSPARENT = new Color(0, 0, 0, 0.25f);
	private static final int DPI = 144;

	/**
	 * The degree of similarity between generated and original image
	 */
	private static final float SIMILARITY_LIMIT = 0.986f;
	
	/**
	 * Comparison resolution: step in pixels in horizontal and vertical directions.
	 */
	private static final int CHECK_RESOLUTION = 1;

	private PAdESService service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument signitureImage;
	/**
	 * PDF-s rotated by pdftk on Ubuntu (<a href="https://packages.ubuntu.com/search?keywords=pdftk">pdftk Ubuntu
	 * packages</a>)<br>
	 * Tool site: <a href="https://www.pdflabs.com/tools/pdftk-the-pdf-toolkit/">pdftk</a>
	 */
	private Map<String, DSSDocument> signablePdfs = new HashMap<>();

	@BeforeEach
	public void init() throws Exception {

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getOfflineCertificateVerifier());

		signitureImage = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/signature.png"));

		signablePdfs.put("normal", new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test.pdf")));
		signablePdfs.put("90", new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_90.pdf")));
		signablePdfs.put("180", new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_180.pdf")));
		signablePdfs.put("270", new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_270.pdf")));
		signablePdfs.put("-90", new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_-90.pdf")));
		signablePdfs.put("-180", new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_-180.pdf")));
		signablePdfs.put("-270", new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_-270.pdf")));
		signablePdfs.put("minoltaScan", new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/sun.pdf"))); // scanner
																															// type
		signablePdfs.put("minoltaScan90", new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/sun_90.pdf"))); // scanner
																																// type
		signablePdfs.put("rotate90", new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/rotate90-rotated.pdf")));
	}

	@Test
	public void pdfRotateDegreeTest() throws IOException {
		service.setPdfObjFactory(new PdfBoxDefaultObjectFactory());
		pdfRotateDegree();
		service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
		pdfRotateDegree();
	}
	
	private void pdfRotateDegree() throws IOException {
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
		service.setPdfObjFactory(new PdfBoxDefaultObjectFactory());
		execute();
		service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
		execute();
	}
	
	private void execute() throws Exception {
		SignatureImageParameters signatureImageParameters = createSignatureImageParameters();

		signatureImageParameters.setRotation(SignatureImageParameters.VisualSignatureRotation.NONE); // default
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

		// check minolta scanner
		signatureImageParameters.setRotation(SignatureImageParameters.VisualSignatureRotation.AUTOMATIC);
		checkImageSimilarityPdf("minoltaScan", "check_sun.pdf");
		/**
		 * sun.pdf and sun90.pdf not equal, when convert it to image (two scanning and the scanner can not scan equal
		 * twice).
		 * So we need the similarity of the sun.pdf and sun90.pdf.
		 * After the signing the visual signature does not have to change the similarity.
		 */
		float sunSimilarity = PdfScreenshotUtils.checkImageSimilarity(pdfToBufferedImage(signablePdfs.get("minoltaScan").openStream()),
				pdfToBufferedImage(signablePdfs.get("minoltaScan90").openStream()), CHECK_RESOLUTION) - 0.015f;
		checkImageSimilarityPdf("minoltaScan90", "check_sun.pdf", sunSimilarity);
	}
	
	@Test
	public void relativePositioningAndRotationtTest() throws Exception {
		service.setPdfObjFactory(new PdfBoxDefaultObjectFactory());
		relativePositioningAndRotation();
		service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
		relativePositioningAndRotation();
	}
	
	private void relativePositioningAndRotation() throws Exception {
		SignatureImageParameters signatureImageParameters = new SignatureImageParameters();
		signatureImageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-pen.png"), "signature-pen.png"));
		signatureParameters.setImageParameters(signatureImageParameters);
		
		signatureImageParameters.setWidth(300);
		signatureImageParameters.setHeight(200);

		signatureImageParameters.setRotation(SignatureImageParameters.VisualSignatureRotation.AUTOMATIC);
		checkImageSimilarityPdf("rotate90", "rotate90_top-left-signed.pdf");
		
		signatureImageParameters.setAlignmentHorizontal(VisualSignatureAlignmentHorizontal.CENTER);
		signatureImageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.BOTTOM);
		checkImageSimilarityPdf("rotate90", "rotate90_bottom-center-signed.pdf");
		
		signatureImageParameters.setAlignmentHorizontal(VisualSignatureAlignmentHorizontal.RIGHT);
		signatureImageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.MIDDLE);
		checkImageSimilarityPdf("rotate90", "rotate90_middle-right-signed.pdf");
		
		signatureImageParameters.setAlignmentHorizontal(VisualSignatureAlignmentHorizontal.RIGHT);
		signatureImageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.BOTTOM);
		checkImageSimilarityPdf("rotate90", "rotate90_bottom-right-signed.pdf");
	}

	@Test
	public void rotateTest() throws Exception {
		SignatureImageParameters signatureImageParameters = createSignatureImageParameters();

		signatureImageParameters.setRotation(SignatureImageParameters.VisualSignatureRotation.AUTOMATIC);
		service.setPdfObjFactory(new PdfBoxDefaultObjectFactory());
		DSSDocument defaultSigned = sign(signablePdfs.get("minoltaScan90"));
		service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
		DSSDocument nativeSigned = sign(signablePdfs.get("minoltaScan90"));
		compareVisualSimilarity(defaultSigned, nativeSigned, SIMILARITY_LIMIT);
	}

	@Test
	@Disabled("for generation and manual testing")
	public void bigGeneratorTest() throws Exception {
		SignatureImageParameters signatureImageParameters = createSignatureImageParameters();

		for (SignatureImageParameters.VisualSignatureRotation rotation : SignatureImageParameters.VisualSignatureRotation.values()) {
			for (SignatureImageParameters.VisualSignatureAlignmentHorizontal horizontal : SignatureImageParameters.VisualSignatureAlignmentHorizontal
					.values()) {
				for (SignatureImageParameters.VisualSignatureAlignmentVertical vertical : SignatureImageParameters.VisualSignatureAlignmentVertical.values()) {
					signatureImageParameters.setRotation(rotation);
					signatureImageParameters.setAlignmentHorizontal(horizontal);
					signatureImageParameters.setAlignmentVertical(vertical);
					String[] pdfs = new String[] { "normal", "90", "180", "270" };
					for (String pdf : pdfs) {
						service.setPdfObjFactory(new PdfBoxDefaultObjectFactory());
						DSSDocument defaultSigned = sign(signablePdfs.get(pdf));
						// defaultSigned.save("target/default_" + rotation + "_" + horizontal + "_" + vertical + "_" + pdf + ".pdf");
						service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
						DSSDocument nativeSigned = sign(signablePdfs.get(pdf));
						// nativeSigned.save("target/native_" + rotation + "_" + horizontal + "_" + vertical + "_" + pdf + ".pdf");
						compareVisualSimilarity(defaultSigned, nativeSigned, SIMILARITY_LIMIT - 0.002f);
					}
				}
			}
		}
	}

	// Pull request 71
	@Test
	public void rotateSunTest() throws Exception {
		
		try (PDDocument inputPDF = PDDocument.load(getClass().getResourceAsStream("/visualSignature/sun.pdf"))) {
			/**
			 * minolta scanner normal(not rotated) pdf and rotation none.
			 *
			 * You can check the pdf rotation by this code:
			 * PDDocument inputPDF = PDDocument.load(getClass().getResourceAsStream("/visualSignature/sun.pdf"));
			 * System.out.println("rotation: " + inputPDF.getPage(0).getRotation());
			 *
			 * result in pdf viewer: signature is top left corner and the sign image line is parallel with the sun eyes line
			 *
			 * comment: this is the original working
			 */
	
			SignatureImageParameters signatureImageParameters = createSignatureImageParameters();
	
			signatureImageParameters.setRotation(SignatureImageParameters.VisualSignatureRotation.NONE);
			service.setPdfObjFactory(new PdfBoxDefaultObjectFactory());
			DSSDocument defaultSigned = sign(signablePdfs.get("minoltaScan"));
			service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
			DSSDocument nativeSigned = sign(signablePdfs.get("minoltaScan"));
			compareVisualSimilarity(defaultSigned, nativeSigned, SIMILARITY_LIMIT);
		}
		
	}

	@Test
	public void rotateSun90Test() throws Exception {
	
		try (PDDocument inputPDF = PDDocument.load(getClass().getResourceAsStream("/visualSignature/sun_90.pdf"))) {
			/**
			 * minolta scanner rotated pdf and rotation none (in pdf view the rotated and normal pdf seem equal)
			 * you can check the pdf rotation by this code:
			 * PDDocument inputPDF = PDDocument.load(getClass().getResourceAsStream("/visualSignature/sun_90.pdf"));
			 * System.out.println("rotation: " + inputPDF.getPage(0).getRotation());
			 *
			 * result in pdf viewer: signature is top right corner and the sign image line is perpendicular with the sun
			 * eyes line
			 *
			 * comment: this is the original working
			 */
	
			SignatureImageParameters signatureImageParameters = createSignatureImageParameters();
	
			signatureImageParameters.setRotation(SignatureImageParameters.VisualSignatureRotation.NONE);
			service.setPdfObjFactory(new PdfBoxDefaultObjectFactory());
			DSSDocument defaultSigned = sign(signablePdfs.get("minoltaScan90"));
			service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
			DSSDocument nativeSigned = sign(signablePdfs.get("minoltaScan90"));
			compareVisualSimilarity(defaultSigned, nativeSigned, SIMILARITY_LIMIT);
	
			/**
			 * minolta scanner rotated pdf and rotation automatic (in pdf view the rotated and normal pdf seem equal)
			 *
			 * result in pdf viewer: signature is top left corner and the sign image line is parallel with the sun eyes
			 * line,
			 * it will be same as with sun.pdf (not rotated) and rotation none
			 */
			signatureImageParameters = createSignatureImageParameters();
	
			signatureImageParameters.setRotation(SignatureImageParameters.VisualSignatureRotation.AUTOMATIC);
			service.setPdfObjFactory(new PdfBoxDefaultObjectFactory());
			defaultSigned = sign(signablePdfs.get("minoltaScan90"));
			service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
			nativeSigned = sign(signablePdfs.get("minoltaScan90"));
			compareVisualSimilarity(defaultSigned, nativeSigned, SIMILARITY_LIMIT);
	
			/**
			 * minolta scanner normal(not rotated) pdf and rotation none.
			 *
			 * result in pdf viewer: signature is top left corner and the sign image line is parallel with the sun eyes
			 * line,
			 * it will be same as with sun.pdf (not rotated) and rotation none
			 */
			signatureImageParameters = createSignatureImageParameters();
	
			signatureImageParameters.setRotation(SignatureImageParameters.VisualSignatureRotation.AUTOMATIC);
			service.setPdfObjFactory(new PdfBoxDefaultObjectFactory());
			defaultSigned = sign(signablePdfs.get("minoltaScan"));
			service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
			nativeSigned = sign(signablePdfs.get("minoltaScan"));
		}
		
	}

	private DSSDocument sign(DSSDocument document) {
		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(document, signatureParameters, signatureValue);
	}

	private void checkRotation(InputStream inputStream, int rotate) throws IOException {
		try (PDDocument document = PDDocument.load(inputStream)) {
			assertEquals(rotate, document.getPages().get(0).getRotation());
		}
	}

	private void checkImageSimilarityPdf(String samplePdf, String checkPdf, float similarity) throws IOException {
		DSSDocument document = sign(signablePdfs.get(samplePdf));
		// document.save("target/test_" + samplePdf + "-" + checkPdf);
		compareVisualSimilarity(document, new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/check/" + checkPdf)), similarity);
	}
	
	private void compareVisualSimilarity(DSSDocument doc1, DSSDocument doc2, float similarity) throws IOException {
		try (InputStream is1 = doc1.openStream(); InputStream is2 = doc2.openStream();
				PDDocument pdDoc1 = PDDocument.load(is1); PDDocument pdDoc2 = PDDocument.load(is2);) {
			PdfScreenshotUtils.checkPdfSimilarity(pdDoc1, pdDoc2, similarity);
		}
	}

	private void checkImageSimilarityPdf(String samplePdf, String checkPdf) throws IOException {
		checkImageSimilarityPdf(samplePdf, checkPdf, SIMILARITY_LIMIT);
	}

	private SignatureImageParameters createSignatureImageParameters() throws Exception {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(signitureImage);
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature\nsecond line\nlong line is very long line with long text example this");
		textParameters.setSignerTextPosition(SignatureImageTextParameters.SignerTextPosition.RIGHT);
		textParameters.setBackgroundColor(TRANSPARENT);
		textParameters.setTextColor(Color.MAGENTA);
		textParameters.setFont(new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSansExtraBold.ttf")));
		textParameters.setSize(8);
		imageParameters.setTextParameters(textParameters);
		imageParameters.setBackgroundColor(TRANSPARENT);
		imageParameters.setxAxis(10);
		imageParameters.setyAxis(20);

		signatureParameters.bLevel().setSigningDate(new Date());

		signatureParameters.setImageParameters(imageParameters);

		return imageParameters;
	}

	private BufferedImage pdfToBufferedImage(InputStream inputStream) throws IOException {
		try (PDDocument document = PDDocument.load(inputStream)) {
			PDFRenderer renderer = new PDFRenderer(document);
			return renderer.renderImageWithDPI(0, DPI);
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
}
