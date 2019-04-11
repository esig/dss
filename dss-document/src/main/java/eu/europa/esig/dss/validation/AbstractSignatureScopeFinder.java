package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.DigestAlgorithm;

public abstract class AbstractSignatureScopeFinder<T extends AdvancedSignature> implements SignatureScopeFinder<T> {
	
	private DigestAlgorithm defaultDigestAlgorithm = DigestAlgorithm.SHA256;
	
	@Override
	public void setDefaultDigestAlgorithm(DigestAlgorithm defaultDigestAlgorithm) {
		this.defaultDigestAlgorithm = defaultDigestAlgorithm;
	}
	
	protected DigestAlgorithm getDigestAlgorithm() {
		return defaultDigestAlgorithm;
	}
	
	protected Digest getDigest(byte[] dataBytes) {
		return new Digest(defaultDigestAlgorithm, DSSUtils.digest(defaultDigestAlgorithm, dataBytes));
	}

}
