package eu.europa.ec.markt.dss.cookbook.example.sign;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.cookbook.example.Cookbook;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.xades.XAdESService;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;

/**
 * How to extend with XAdES-BASELINE-T
 */
public class ExtendSignXmlXadesBToT extends Cookbook {

	public static void main(final String[] args) throws IOException {

		toExtendDocument = new FileDocument("signedXmlXadesB.xml");

		SignatureParameters parameters = new SignatureParameters();
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);

		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		XAdESService xadesService = new XAdESService(certificateVerifier);
		xadesService.setTspSource(getMockTSPSource());

		DSSDocument extendedDocument = xadesService.extendDocument(toExtendDocument, parameters);

		//DSSUtils.copy(extendedDocument.openStream(), System.out);
		InputStream is = new ByteArrayInputStream(extendedDocument.getBytes());
		DSSUtils.saveToFile(is, "extendedSignedXmlXadesBToT.xml");
	}
}