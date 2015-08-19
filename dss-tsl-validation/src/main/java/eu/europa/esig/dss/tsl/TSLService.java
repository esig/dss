package eu.europa.esig.dss.tsl;

import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import eu.europa.esig.dss.x509.CertificateToken;

public class TSLService {

	private String name;
	private String status;
	private String type;
	private Date startDate;
	private Date endDate;
	private List<CertificateToken> certificates;
	private List<X500Principal> x500Principals;

	private List<TSLServiceExtension> extensions;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public Date getStartDate() {
		return startDate;
	}

	public void setStartDate(Date startDate) {
		this.startDate = startDate;
	}

	public Date getEndDate() {
		return endDate;
	}

	public void setEndDate(Date endDate) {
		this.endDate = endDate;
	}

	public List<CertificateToken> getCertificates() {
		return certificates;
	}

	public void setCertificates(List<CertificateToken> certificates) {
		this.certificates = certificates;
	}

	public List<X500Principal> getX500Principals() {
		return x500Principals;
	}

	public void setX500Principals(List<X500Principal> x500Principals) {
		this.x500Principals = x500Principals;
	}

	public List<TSLServiceExtension> getExtensions() {
		return extensions;
	}

	public void setExtensions(List<TSLServiceExtension> extensions) {
		this.extensions = extensions;
	}

}
