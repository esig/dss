package eu.europa.esig.dss.diagnostic;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.enumerations.CertificateOrigin;

public class RelatedCertificateWrapper extends CertificateWrapper {
	
	private final XmlRelatedCertificate relatedCertificate;

	public RelatedCertificateWrapper(XmlRelatedCertificate relatedCertificate) {
		super(relatedCertificate.getCertificate());
		this.relatedCertificate = relatedCertificate;
	}
	
	public List<CertificateOrigin> getOrigins() {
		return relatedCertificate.getOrigins();
	}
	
	public List<CertificateRefWrapper> getReferences() {
		List<CertificateRefWrapper> references = new ArrayList<>();
		for (XmlCertificateRef certificateRef : relatedCertificate.getCertificateRefs()) {
			references.add(new CertificateRefWrapper(certificateRef));
		}
		return references;
	}

}
