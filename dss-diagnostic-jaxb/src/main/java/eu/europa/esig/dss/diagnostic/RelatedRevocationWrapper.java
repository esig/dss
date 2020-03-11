package eu.europa.esig.dss.diagnostic;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocationRef;
import eu.europa.esig.dss.enumerations.RevocationOrigin;

public class RelatedRevocationWrapper extends RevocationWrapper {
	
	private final XmlRelatedRevocation relatedRevocation;

	public RelatedRevocationWrapper(XmlRelatedRevocation relatedRevocation) {
		super(relatedRevocation.getRevocation());
		this.relatedRevocation = relatedRevocation;
	}
	
	public List<RevocationOrigin> getOrigins() {
		return relatedRevocation.getOrigins();
	}
	
	public List<RevocationRefWrappper> getReferences() {
		List<RevocationRefWrappper> references = new ArrayList<>();
		for (XmlRevocationRef revocationRef : relatedRevocation.getRevocationRefs()) {
			references.add(new RevocationRefWrappper(revocationRef));
		}
		return references;
	}

}
