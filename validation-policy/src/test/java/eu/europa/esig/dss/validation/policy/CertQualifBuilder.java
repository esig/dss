package eu.europa.esig.dss.validation.policy;

public class CertQualifBuilder {

	private CertQualifBuilder() {
	}

	public static CertificateQualification getNoQualif() {
		CertificateQualification cq = new CertificateQualification();
		return cq;
	}

	public static CertificateQualification getQcpOnly() {
		CertificateQualification cq = new CertificateQualification();
		cq.setQcp(true);
		return cq;
	}

	public static CertificateQualification getQccOnly() {
		CertificateQualification cq = new CertificateQualification();
		cq.setQcc(true);
		return cq;
	}

	public static CertificateQualification getQcppOnly() {
		CertificateQualification cq = new CertificateQualification();
		cq.setQcpp(true);
		return cq;
	}

	public static CertificateQualification getQcsscdOnly() {
		CertificateQualification cq = new CertificateQualification();
		cq.setQcsscd(true);
		return cq;
	}

	public static CertificateQualification getQcpQcc() {
		CertificateQualification cq = new CertificateQualification();
		cq.setQcp(true);
		cq.setQcc(true);
		return cq;
	}

	public static CertificateQualification getQcpQccQcsscd() {
		CertificateQualification cq = new CertificateQualification();
		cq.setQcp(true);
		cq.setQcc(true);
		cq.setQcsscd(true);
		return cq;
	}

	public static CertificateQualification getQcppQcc() {
		CertificateQualification cq = new CertificateQualification();
		cq.setQcpp(true);
		cq.setQcc(true);
		return cq;
	}

	public static CertificateQualification getQcppQcsscd() {
		CertificateQualification cq = new CertificateQualification();
		cq.setQcpp(true);
		cq.setQcc(true);
		cq.setQcsscd(true);
		return cq;
	}

	public static CertificateQualification getQccQcsscd() {
		CertificateQualification cq = new CertificateQualification();
		cq.setQcc(true);
		cq.setQcsscd(true);
		return cq;
	}

}
