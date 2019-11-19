package eu.europa.esig.dss.xades.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class ImpossibleExtensionTest extends PKIFactoryAccess {

	@Test
	public void xmldsig() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/xmldsig-only.xml");

		XAdESService service = new XAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		DSSException exception = assertThrows(DSSException.class, () -> service.extendDocument(doc, parameters));
		assertEquals("The signature does not contain QualifyingProperties element (or contains more than one)! Extension is not possible.",
				exception.getMessage());
	}

	@Test
	public void notSigned() {
		DSSDocument doc = new FileDocument("src/test/resources/sample.xml");

		XAdESService service = new XAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		DSSException exception = assertThrows(DSSException.class, () -> service.extendDocument(doc, parameters));
		assertEquals("There is no signature to extend!", exception.getMessage());
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
