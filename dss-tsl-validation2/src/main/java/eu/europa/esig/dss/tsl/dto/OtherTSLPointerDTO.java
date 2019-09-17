package eu.europa.esig.dss.tsl.dto;

import java.util.List;

import eu.europa.esig.dss.model.x509.CertificateToken;

public class OtherTSLPointerDTO {

	private final String location;
	private final List<CertificateToken> certificates;

	public OtherTSLPointerDTO(String location, List<CertificateToken> certificates) {
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
