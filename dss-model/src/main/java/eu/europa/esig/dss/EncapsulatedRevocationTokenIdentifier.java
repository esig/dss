package eu.europa.esig.dss;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.x509.RevocationOrigin;

public class EncapsulatedRevocationTokenIdentifier extends EncapsulatedTokenIdentifier {

	private static final long serialVersionUID = -562828035596645649L;
	
	private List<RevocationOrigin> origins = new ArrayList<RevocationOrigin>();

	public EncapsulatedRevocationTokenIdentifier(byte[] binaries) {
		super(binaries);
	}
	
	protected EncapsulatedRevocationTokenIdentifier(byte[] binaries, RevocationOrigin origin) {
		this(binaries);
		addOrigin(origin);
	}
	
	public void addOrigin(RevocationOrigin origin) {
		if (origin != null && !origins.contains(origin)) {
			origins.add(origin);
		}
	}
	
	public List<RevocationOrigin> getOrigins() {
		return origins;
	}
	
	@Override
	public String asXmlId() {
		return "R-" + super.asXmlId();
	}
	
}
