package eu.europa.esig.dss;

import java.util.LinkedList;
import java.util.List;

import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.SignatureParametersBuilder;
import eu.europa.esig.dss.model.x509.CertificateToken;

@SuppressWarnings("rawtypes")
public abstract class AbstractSignatureParametersBuilder<SP extends AbstractSignatureParameters> implements SignatureParametersBuilder<SP> {
	
	/**
	 * A signing certificate to be used for a signature creation
	 */
	private final CertificateToken signingCertificate;

	/**
	 * A certificate chain of the signing certificate
	 */
	private List<CertificateToken> certificateChain;
	
	/**
	 * BLevelParameters
	 */
	private BLevelParameters bLevelParams = new BLevelParameters();
	
	/**
	 * The default constructor
	 * 
	 * @param signingCertificate {@link CertificateToken}
	 */
	protected AbstractSignatureParametersBuilder(CertificateToken signingCertificate) {
		this(signingCertificate, new LinkedList<>());
	}

	/**
	 * A constructor with a certificateChain
	 * 
	 * @param signingCertificate {@link CertificateToken}
	 * @param certificateChain a list of {@link CertificateToken}s
	 */
	protected AbstractSignatureParametersBuilder(CertificateToken signingCertificate, List<CertificateToken> certificateChain) {
		this.signingCertificate = signingCertificate;
		this.certificateChain = certificateChain;
	}
	
	/**
	 * Initialize and return empty signature parameters
	 * 
	 * @return {@code SP} signature parameters
	 */
	protected abstract SP initParameters();
	
	/**
	 * Returns {@code BLevelParameters}
	 * 
	 * @return {@link BLevelParameters}
	 */
	public BLevelParameters bLevel() {
		return bLevelParams;
	}

	/**
	 * Sets a BLevelParameters (e.g. a SigningDate)
	 * 
	 * @param bLevelParams {@link BLevelParameters} to be used
	 * @return the builder
	 */
	public AbstractSignatureParametersBuilder<SP> setBLevelParams(BLevelParameters bLevelParams) {
		this.bLevelParams = bLevelParams;
		return this;
	}
	
	@Override
	@SuppressWarnings("unchecked")
	public SP build() {
		SP signatureParameters = initParameters();
		signatureParameters.setSigningCertificate(signingCertificate);
		signatureParameters.setCertificateChain(certificateChain);
		signatureParameters.setBLevelParams(bLevelParams);
		return signatureParameters;
	}

}
