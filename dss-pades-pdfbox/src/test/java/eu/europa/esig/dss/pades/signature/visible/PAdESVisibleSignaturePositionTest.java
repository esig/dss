/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.signature.visible;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.io.RandomAccessRead;
import org.apache.pdfbox.io.RandomAccessReadBuffer;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Tag("slow")
class PAdESVisibleSignaturePositionTest extends AbstractTestVisualComparator {

	private static final Color TRANSPARENT = new Color(0, 0, 0, 0.25f);
	private static final int DPI = 144;

	/**
	 * The degree of similarity between generated and original image
	 */
	private static final float DEFAULT_SIMILARITY_LIMIT = 0.983f;
	
	/**
	 * Comparison resolution: step in pixels in horizontal and vertical directions.
	 */
	private static final int CHECK_RESOLUTION = 1;

	private String testName;
	private PAdESService service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	
	private DSSDocument signatureImage;

	private float similarityLimit;
	
	/**
	 * PDF-s rotated by pdftk on Ubuntu (<a href="https://packages.ubuntu.com/search?keywords=pdftk">pdftk Ubuntu
	 * packages</a>)<br>
	 * Tool site: <a href="https://www.pdflabs.com/tools/pdftk-the-pdf-toolkit/">pdftk</a>
	 */
	private Map<String, DSSDocument> signablePdfs = new HashMap<>();

	@BeforeEach
	void init() throws Exception {

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getOfflineCertificateVerifier());

		signatureImage = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/signature.png"));

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

		similarityLimit = DEFAULT_SIMILARITY_LIMIT;
	}

	@Test
	void pdfRotateDegreeTest() throws IOException {
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
	void rotationTest() throws Exception {
		SignatureImageParameters signatureImageParameters = createSignatureImageParameters();
		SignatureFieldParameters fieldParameters = signatureImageParameters.getFieldParameters();

		fieldParameters.setRotation(VisualSignatureRotation.NONE); // default
		checkImageSimilarityPdf("normal", "check_custom_10_20.pdf");
		checkImageSimilarityPdf("90", "check_custom_rotate_none_90_10_20.pdf");
		checkImageSimilarityPdf("180", "check_custom_rotate_none_180_10_20.pdf");
		checkImageSimilarityPdf("270", "check_custom_rotate_none_270_10_20.pdf");
		checkImageSimilarityPdf("-270", "check_custom_rotate_none_90_10_20.pdf");
		checkImageSimilarityPdf("-180", "check_custom_rotate_none_180_10_20.pdf");
		checkImageSimilarityPdf("-90", "check_custom_rotate_none_270_10_20.pdf");
		fieldParameters.setRotation(VisualSignatureRotation.AUTOMATIC);
		checkImageSimilarityPdf("normal", "check_custom_10_20.pdf");
		checkImageSimilarityPdf("90", "check_custom_rotate_automatic_90_10_20.pdf");
		checkImageSimilarityPdf("180", "check_custom_rotate_automatic_180_10_20.pdf");
		checkImageSimilarityPdf("270", "check_custom_rotate_automatic_270_10_20.pdf");
		checkImageSimilarityPdf("-270", "check_custom_rotate_automatic_90_10_20.pdf");
		checkImageSimilarityPdf("-180", "check_custom_rotate_automatic_180_10_20.pdf");
		checkImageSimilarityPdf("-90", "check_custom_rotate_automatic_270_10_20.pdf");
		fieldParameters.setRotation(VisualSignatureRotation.ROTATE_270);
		checkImageSimilarityPdf("normal", "check_custom_rotate270_10_20.pdf");
		checkImageSimilarityPdf("90", "check_custom_rotate270_90_10_20.pdf");
		checkImageSimilarityPdf("180", "check_custom_rotate270_180_10_20.pdf");
		checkImageSimilarityPdf("270", "check_custom_rotate270_270_10_20.pdf");
		checkImageSimilarityPdf("-270", "check_custom_rotate270_90_10_20.pdf");
		checkImageSimilarityPdf("-180", "check_custom_rotate270_180_10_20.pdf");
		checkImageSimilarityPdf("-90", "check_custom_rotate270_270_10_20.pdf");
		fieldParameters.setRotation(VisualSignatureRotation.ROTATE_180);
		checkImageSimilarityPdf("normal", "check_custom_rotate180_10_20.pdf");
		fieldParameters.setRotation(VisualSignatureRotation.ROTATE_90);
		checkImageSimilarityPdf("normal", "check_custom_rotate90_10_20.pdf");

		// check minolta scanner
		fieldParameters.setRotation(VisualSignatureRotation.AUTOMATIC);
		checkImageSimilarityPdf("minoltaScan", "check_sun.pdf");
		
		/**
		 * sun.pdf and sun90.pdf not equal, when convert it to image (two scanning and the scanner can not scan equal
		 * twice).
		 * So we need the similarity of the sun.pdf and sun90.pdf.
		 * After the signing the visual signature does not have to change the similarity.
		 */
		float sunSimilarity = checkImageSimilarity(pdfToBufferedImage(signablePdfs.get("minoltaScan").openStream()),
				pdfToBufferedImage(signablePdfs.get("minoltaScan90").openStream()), CHECK_RESOLUTION) - 0.015f;
		checkImageSimilarityPdf("minoltaScan90", "check_sun.pdf", sunSimilarity);
	}
	
	@Test
	void relativePositioningTest() throws Exception {
		SignatureImageParameters signatureImageParameters = new SignatureImageParameters();
		signatureImageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-pen.png"), "signature-pen.png"));
		signatureParameters.setImageParameters(signatureImageParameters);
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setWidth(300);
		fieldParameters.setHeight(200);
		fieldParameters.setRotation(VisualSignatureRotation.AUTOMATIC);
		signatureImageParameters.setFieldParameters(fieldParameters);

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
	@Disabled("for generation and manual testing")
	void bigGeneratorTest() throws Exception {
		SignatureImageParameters signatureImageParameters = createSignatureImageParameters();
		similarityLimit = 0.981f;
		for (VisualSignatureRotation rotation : VisualSignatureRotation.values()) {
			for (VisualSignatureAlignmentHorizontal horizontal : VisualSignatureAlignmentHorizontal.values()) {
				for (VisualSignatureAlignmentVertical vertical : VisualSignatureAlignmentVertical.values()) {
					signatureImageParameters.getFieldParameters().setRotation(rotation);
					signatureImageParameters.setAlignmentHorizontal(horizontal);
					signatureImageParameters.setAlignmentVertical(vertical);
					String[] pdfs = new String[] { "normal", "90", "180", "270" };
					for (String pdf : pdfs) {
						documentToSign = signablePdfs.get(pdf);
						drawAndCompareVisually();
					}
				}
			}
		}
	}

	// Pull request 71
	@Test
	void rotateSunTest() throws Exception {
		
		try (InputStream is = getClass().getResourceAsStream("/visualSignature/sun.pdf");
			 RandomAccessRead rar = new RandomAccessReadBuffer(is);
			 PDDocument inputPDF = Loader.loadPDF(rar)) {
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
			signatureImageParameters.getFieldParameters().setRotation(VisualSignatureRotation.NONE);
			
			documentToSign = signablePdfs.get("minoltaScan");
			testName = "rotateSunTest";
			drawAndCompareVisually();
		}
		
	}

	@Test
	void rotateSun90Test() throws Exception {

		try (InputStream is = getClass().getResourceAsStream("/visualSignature/sun_90.pdf");
			 RandomAccessRead rar = new RandomAccessReadBuffer(is);
			 PDDocument inputPDF = Loader.loadPDF(rar)) {
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
			signatureImageParameters.getFieldParameters().setRotation(VisualSignatureRotation.NONE);
			
			documentToSign = signablePdfs.get("minoltaScan90");
			testName = "rotateSun90TestNONE";
			drawAndCompareVisually();
	
			/**
			 * minolta scanner rotated pdf and rotation automatic (in pdf view the rotated and normal pdf seem equal)
			 *
			 * result in pdf viewer: signature is top left corner and the sign image line is parallel with the sun eyes
			 * line,
			 * it will be same as with sun.pdf (not rotated) and rotation none
			 */
			signatureImageParameters = createSignatureImageParameters();
			signatureImageParameters.getFieldParameters().setRotation(VisualSignatureRotation.AUTOMATIC);
			
			documentToSign = signablePdfs.get("minoltaScan90");
			testName = "rotateSun90TestAUTOMATIC";
			drawAndCompareVisually();
	
			/**
			 * minolta scanner normal(not rotated) pdf and rotation none.
			 *
			 * result in pdf viewer: signature is top left corner and the sign image line is parallel with the sun eyes
			 * line,
			 * it will be same as with sun.pdf (not rotated) and rotation none
			 */
			signatureImageParameters = createSignatureImageParameters();
			signatureImageParameters.getFieldParameters().setRotation(VisualSignatureRotation.AUTOMATIC);
			
			documentToSign = signablePdfs.get("minoltaScan");
			testName = "rotateSunTestAUTOMATIC";
			drawAndCompareVisually();
		}
		
	}

	private void checkRotation(InputStream inputStream, int rotate) throws IOException {
		try (InputStream is = inputStream;
			 RandomAccessRead rar = new RandomAccessReadBuffer(is);
			 PDDocument document = Loader.loadPDF(rar)) {
			assertEquals(rotate, document.getPages().get(0).getRotation());
		}
	}

	private void checkImageSimilarityPdf(String samplePdf, String checkPdf) throws IOException {
		checkImageSimilarityPdf(samplePdf, checkPdf, DEFAULT_SIMILARITY_LIMIT);
	}

	private void checkImageSimilarityPdf(String samplePdf, String checkPdf, float similaritylevel) throws IOException {
		testName = samplePdf + "_" + checkPdf;
		documentToSign = signablePdfs.get(samplePdf);

		getService().setPdfObjFactory(new PdfBoxDefaultObjectFactory());
		DSSDocument defaultDrawerPdf = sign(getTestName() + "_default");
		getService().setPdfObjFactory(new PdfBoxNativeObjectFactory());
		DSSDocument nativeDrawerPdf = sign(getTestName() + "_native");
		compareVisualSimilarity(defaultDrawerPdf, nativeDrawerPdf, similaritylevel);
		
		compareVisualSimilarity(nativeDrawerPdf, new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/check/" + checkPdf)), similaritylevel);
	}

	private SignatureImageParameters createSignatureImageParameters() throws Exception {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(signatureImage);
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature\nsecond line\nlong line is very long line with long text example this");
		textParameters.setSignerTextPosition(SignerTextPosition.RIGHT);
		textParameters.setBackgroundColor(TRANSPARENT);
		textParameters.setTextColor(Color.MAGENTA);
		DSSFileFont font = new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSansExtraBold.ttf"));
		font.setSize(8);
		textParameters.setFont(font);
		imageParameters.setTextParameters(textParameters);
		imageParameters.setBackgroundColor(TRANSPARENT);
		

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(10);
		fieldParameters.setOriginY(20);
		imageParameters.setFieldParameters(fieldParameters);

		signatureParameters.bLevel().setSigningDate(new Date());

		signatureParameters.setImageParameters(imageParameters);

		return imageParameters;
	}

	private BufferedImage pdfToBufferedImage(InputStream inputStream) throws IOException {
		try (InputStream is = inputStream;
			 RandomAccessRead rar = new RandomAccessReadBuffer(is);
			 PDDocument document = Loader.loadPDF(rar)) {
			PDFRenderer renderer = new PDFRenderer(document);
			return renderer.renderImageWithDPI(0, DPI);
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected String getTestName() {
		return testName;
	}

	@Override
	protected PAdESService getService() {
		return service;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected PAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	public float getSimilarityLimit() {
		return similarityLimit;
	}

}
