package eu.europa.esig.dss.cades.validation;

import java.security.PublicKey;

import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.spi.x509.SignatureIntegrityValidator;

public class CAdESSignatureIntegrityValidator extends SignatureIntegrityValidator {
	
	private final SignerInformation signerInformation;
	
	private final JcaSimpleSignerInfoVerifierBuilder verifier;
	
	public CAdESSignatureIntegrityValidator(final SignerInformation signerInformation) {
		this.signerInformation = signerInformation;
		this.verifier = instantiateVerifier();
	}
	
	private JcaSimpleSignerInfoVerifierBuilder instantiateVerifier() {
		final JcaSimpleSignerInfoVerifierBuilder verifier = new JcaSimpleSignerInfoVerifierBuilder();
		verifier.setProvider(DSSSecurityProvider.getSecurityProviderName());
		return verifier;
	}

	@Override
	protected boolean verify(PublicKey publicKey) throws DSSException {
		try {
			final SignerInformationVerifier signerInformationVerifier = verifier.build(publicKey);
			return signerInformation.verify(signerInformationVerifier);
		} catch (CMSSignerDigestMismatchException e) {
			throw new DSSException(String.format("Unable to validate CMS Signature : %s", e.getMessage()));
		} catch (Exception e) {
			throw new DSSException(String.format("Unable to validate CMS Signature : %s", e.getMessage()), e);
		}
	}

}
