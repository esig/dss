package eu.europa.esig.dss;

import java.util.EnumMap;

public abstract class EncapsulatedTokenIdentifier extends Identifier {

	private static final long serialVersionUID = 8499261315144968564L;

	private final byte[] binaries;

	private final EnumMap<DigestAlgorithm, byte[]> digestMap = new EnumMap<DigestAlgorithm, byte[]>(DigestAlgorithm.class);
	
	EncapsulatedTokenIdentifier(byte[] binaries) {
		super(binaries);
		this.binaries = binaries;
	}
	
	public byte[] getBinaries() {
		return binaries;
	}
	
	public byte[] getDigestValue(DigestAlgorithm digestAlgorithm) {
		byte[] digestValue = digestMap.get(digestAlgorithm);
		if (digestValue == null) {
			digestValue = digestAlgorithm.getMessageDigest().digest(getBinaries());
			digestMap.put(digestAlgorithm, digestValue);
		}
		return digestValue;
	}

}
