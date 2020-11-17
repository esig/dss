package eu.europa.esig.dss.asic.cades.signature.asice;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.test.PKIFactoryAccess;

public class ASiCECAdESAddSignaturePolicyStoreXAdESTest extends PKIFactoryAccess {

	private static final String HTTP_SPURI_TEST = "http://spuri.test";
	private static final DSSDocument POLICY_CONTENT = new FileDocument("src/test/resources/signature-policy.der");

	@Test
	public void test() {
		DSSDocument documentToSign = new FileDocument("src/test/resources/signable/asic_xades.zip");

		ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

		ASiCWithCAdESService service = new ASiCWithCAdESService(getOfflineCertificateVerifier());

		SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();
		signaturePolicyStore.setSignaturePolicyContent(POLICY_CONTENT);
		SpDocSpecification spDocSpec = new SpDocSpecification();
		spDocSpec.setId(HTTP_SPURI_TEST);
		signaturePolicyStore.setSpDocSpecification(spDocSpec);

		Exception exception = assertThrows(UnsupportedOperationException.class,
				() -> service.addSignaturePolicyStore(documentToSign, signaturePolicyStore));
		assertEquals("Signature documents of the expected format are not found in the provided ASiC Container! "
				+ "Add a SignaturePolicyStore is not possible!", exception.getMessage());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
