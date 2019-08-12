package eu.europa.esig.dss.model.identifier;

import java.util.EnumMap;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;

/**
 * This class is used to obtain a requested digest from a stored binary array
 */
public abstract class MultipleDigestIdentifier extends Identifier {

	private static final long serialVersionUID = 8499261315144968564L;

	private final byte[] binaries;

	private final EnumMap<DigestAlgorithm, byte[]> digestMap = new EnumMap<DigestAlgorithm, byte[]>(DigestAlgorithm.class);
	
	protected MultipleDigestIdentifier(byte[] binaries) {
		super(binaries);
		this.binaries = binaries;
		
		Digest id = getDigestId();
		digestMap.put(id.getAlgorithm(), id.getValue());
	}
	
	public byte[] getBinaries() {
		return binaries;
	}
	
	public byte[] getDigestValue(DigestAlgorithm digestAlgorithm) {
		byte[] digestValue = digestMap.get(digestAlgorithm);
		if (digestValue == null) {
			digestValue = getMessageDigest(digestAlgorithm).digest(getBinaries());
			digestMap.put(digestAlgorithm, digestValue);
		}
		return digestValue;
	}

}
