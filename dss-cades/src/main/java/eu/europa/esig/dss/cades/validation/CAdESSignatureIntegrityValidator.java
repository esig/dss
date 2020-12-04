package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.spi.x509.SignatureIntegrityValidator;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;

import java.security.PublicKey;

/**
 * Validates integrity of a CAdES signature
 */
public class CAdESSignatureIntegrityValidator extends SignatureIntegrityValidator {

	/** The corresponding SignerInformation */
	private final SignerInformation signerInformation;

	/** The instance of the verifier builder */
	private final JcaSimpleSignerInfoVerifierBuilder verifier;

	/**
	 * The default constructor
	 *
	 * @param signerInformation {@link SignerInformation} to be validated
	 */
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
