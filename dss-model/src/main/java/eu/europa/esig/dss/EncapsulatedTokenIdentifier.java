package eu.europa.esig.dss;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;

import eu.europa.esig.dss.x509.RevocationOrigin;

public abstract class EncapsulatedTokenIdentifier extends Identifier {

	private static final long serialVersionUID = 8499261315144968564L;

	private final byte[] binaries;
	private List<RevocationOrigin> origins = new ArrayList<RevocationOrigin>();

	protected EnumMap<DigestAlgorithm, byte[]> digestMap = new EnumMap<DigestAlgorithm, byte[]>(DigestAlgorithm.class);
	
	EncapsulatedTokenIdentifier(byte[] binaries) {
		super(binaries);
		this.binaries = binaries;
	}

	EncapsulatedTokenIdentifier(byte[] binaries, RevocationOrigin origin) {
		super(binaries);
		this.binaries = binaries;
		this.origins.add(origin);
	}
	
	public byte[] getBinaries() {
		return binaries;
	}
	
	public List<RevocationOrigin> getOrigins() {
		return origins;
	}
	
	public void addOrigin(RevocationOrigin origin) {
		if (!origins.contains(origin)) {
			origins.add(origin);
		}
	}
	
	public byte[] getDigestValue(DigestAlgorithm digestAlgorithm) {
		return digestMap.get(digestAlgorithm);
	}

}
