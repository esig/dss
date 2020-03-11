package eu.europa.esig.dss.diagnostic;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificate;
import eu.europa.esig.dss.enumerations.CertificateOrigin;

public class OrphanCertificateWrapper extends OrphanTokenWrapper {
	
	private final XmlOrphanCertificate orphanCertificate;
	
	public OrphanCertificateWrapper(final XmlOrphanCertificate orphanCertificate) {
		super(orphanCertificate.getToken());
		this.orphanCertificate = orphanCertificate;
	}
	
	/**
	 * Returns a list of orphan certificate origins
	 * 
	 * @return a list of {@link CertificateOrigin}s
	 */
	public List<CertificateOrigin> getOrigins() {
		return orphanCertificate.getOrigins();
	}
	
	/**
	 * Returns a list of orphan certificate references
	 * 
	 * @return a list of {@link CertificateRefWrapper}s
	 */
	public List<CertificateRefWrapper> getReferences() {
		List<CertificateRefWrapper> certificateRefWrappers = new ArrayList<>();
		
		List<XmlCertificateRef> certificateRefs = orphanCertificate.getCertificateRefs();
		for (XmlCertificateRef certificateRef : certificateRefs) {
			certificateRefWrappers.add(new CertificateRefWrapper(certificateRef));
		}
		return certificateRefWrappers;
	}

}
