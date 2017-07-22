package eu.europa.dss.signature.policy.validation;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

import org.bouncycastle.cms.CMSException;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.TokenIdentifier;
import eu.europa.esig.dss.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.crl.CRLToken;

public class FullCAdESSignaturePolicyValidatorTest {
	
	@Test
	public void shouldValidateWhenPadesPbadAdrb() throws IOException, CMSException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/AD-RT-bry-ts-oid-uri.pdf")));

		validator.setCertificateVerifier(new CommonCertificateVerifier());
		List<AdvancedSignature> signatures = validator.getSignatures();
		PAdESSignature sig = (PAdESSignature) signatures.get(0);
		
		CertificateTestUtils.loadIssuers(sig.getSigningCertificateToken(), sig.getCertPool());
		mockRevocation(sig.getSigningCertificateToken());
		SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
		signaturePolicyProvider.setDataLoader(new NativeHTTPDataLoader());
		FullCAdESSignaturePolicyValidator cadesValidator = new FullCAdESSignaturePolicyValidator(signaturePolicyProvider, sig);
		Map<String, String> errors = cadesValidator.validate();
		Assert.assertTrue("FullCAdESSignaturePolicyValidator errors: " + errors.toString(), errors.isEmpty());
	}

	private void mockRevocation(CertificateToken certificateToken) {
		RevocationToken revTk = Mockito.mock(CRLToken.class);
		Mockito.doReturn("fake_contants".getBytes()).when(revTk).getEncoded();
		Mockito.doReturn(new TokenIdentifier(revTk)).when(revTk).getDSSId();
		Mockito.doReturn(true).when(revTk).getStatus();
		Mockito.doReturn(true).when(revTk).isValid();
		while(certificateToken != null) {
			certificateToken.addRevocationToken(revTk);
			certificateToken = certificateToken.getIssuerToken();
		}
	}
}
