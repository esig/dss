package eu.europa.esig.dss.cades.validation.dss1419;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.cades.validation.AbstractCAdESTestValidation;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class DSS1419Sha3224RsaTest extends AbstractCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss-1419/CAdES-BpB-att-SHA3_224-SHA3_224withRSA.p7m");
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		
		assertEquals(1, signatures.size());
		CAdESSignature cades = (CAdESSignature) signatures.get(0);

		Set<DigestAlgorithm> messageDigestAlgorithms = cades.getMessageDigestAlgorithms();
		assertEquals(1, signatures.size());
		assertEquals(DigestAlgorithm.SHA3_224, messageDigestAlgorithms.iterator().next());
		assertNotNull(cades.getMessageDigestValue());

		assertEquals(EncryptionAlgorithm.RSA, cades.getEncryptionAlgorithm());
		assertEquals(DigestAlgorithm.SHA3_224, cades.getDigestAlgorithm());
		assertNull(cades.getMaskGenerationFunction());
	}

}
