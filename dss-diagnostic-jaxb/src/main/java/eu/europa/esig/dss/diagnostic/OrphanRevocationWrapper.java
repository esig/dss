package eu.europa.esig.dss.diagnostic;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocationRef;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;

public class OrphanRevocationWrapper extends OrphanTokenWrapper {
	
	private final XmlOrphanRevocation orphanRevocation;
	
	public OrphanRevocationWrapper(final XmlOrphanRevocation orphanRevocation) {
		super(orphanRevocation.getToken());
		this.orphanRevocation = orphanRevocation;
	}
	
	/**
	 * Returns a revocation data type (CRL or OCSP)
	 * 
	 * @return {@link RevocationType}
	 */
	public RevocationType getRevocationType() {
		return orphanRevocation.getType();
	}
	
	/**
	 * Returns a list of orphan revocation origins
	 * 
	 * @return a list of {@link RevocationOrigin}s
	 */
	public List<RevocationOrigin> getOrigins() {
		return orphanRevocation.getOrigins();
	}
	
	/**
	 * Returns a list of orphan revocation references
	 * 
	 * @return a list of {@link RevocationRefWrappper}s
	 */
	public List<RevocationRefWrappper> getReferences() {
		List<RevocationRefWrappper> revocationRefWrappers = new ArrayList<>();
		
		List<XmlRevocationRef> revocationRefs = orphanRevocation.getRevocationRefs();
		for (XmlRevocationRef revocationRef : revocationRefs) {
			revocationRefWrappers.add(new RevocationRefWrappper(revocationRef));
		}
		return revocationRefWrappers;
	}

}
