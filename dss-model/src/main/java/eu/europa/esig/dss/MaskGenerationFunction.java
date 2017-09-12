package eu.europa.esig.dss;

public enum MaskGenerationFunction {

	MGF1_SHA1(DigestAlgorithm.SHA1, 20),

	MGF1_SHA224(DigestAlgorithm.SHA224, 28),

	MGF1_SHA256(DigestAlgorithm.SHA256, 32),

	MGF1_SHA384(DigestAlgorithm.SHA384, 48),

	MGF1_SHA512(DigestAlgorithm.SHA512, 64);

	private final DigestAlgorithm digestAlgorithm;
	private final int saltLength;

	private MaskGenerationFunction(DigestAlgorithm digestAlgorithm, int saltLength) {
		this.digestAlgorithm = digestAlgorithm;
		this.saltLength = saltLength;
	}

	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	public int getSaltLength() {
		return saltLength;
	}

}
