package eu.europa.esig.dss.pades.signature.visible;

import java.awt.Color;
import java.util.Date;

import org.junit.jupiter.api.BeforeEach;

import com.lowagie.text.pdf.BaseFont;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.suite.AbstractPAdESTestSignature;
import eu.europa.esig.dss.pdf.openpdf.visible.ITextNativeFont;
import eu.europa.esig.dss.signature.DocumentSignatureService;

public class ITextDSSNativeFontTest extends AbstractPAdESTestSignature {

	private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		
		SignatureImageParameters signatureImageParameters = new SignatureImageParameters();
		
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature\nOne more line\nAnd the last line");
		textParameters.setTextColor(Color.BLUE);
		textParameters.setBackgroundColor(Color.YELLOW);
		textParameters.setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.CENTER);
		
		BaseFont baseFont = BaseFont.createFont(BaseFont.HELVETICA, BaseFont.CP1252, false);
		textParameters.setFont(new ITextNativeFont(baseFont));
		
		signatureImageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(signatureImageParameters);

		service = new PAdESService(getOfflineCertificateVerifier());
	}

	@Override
	protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected PAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
