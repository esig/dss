package eu.europa.esig.dss.spi.tsl;

import java.io.Serializable;
import java.util.List;

import eu.europa.esig.dss.model.x509.CertificateToken;

public class OtherTSLPointer implements Serializable {

	private static final long serialVersionUID = 3015076999802292662L;
	
	private final String location;
	private final List<CertificateToken> certificates;

	public OtherTSLPointer(String location, List<CertificateToken> certificates) {
		this.location = location;
		this.certificates = certificates;
	}

	public String getLocation() {
		return location;
	}

	public List<CertificateToken> getCertificates() {
		return certificates;
	}

}
