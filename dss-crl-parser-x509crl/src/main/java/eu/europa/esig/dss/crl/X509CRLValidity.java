package eu.europa.esig.dss.crl;

import java.security.cert.X509CRL;

public class X509CRLValidity extends CRLValidity {

	private X509CRL x509CRL;

	public X509CRL getX509CRL() {
		return x509CRL;
	}

	public void setX509CRL(X509CRL x509crl) {
		x509CRL = x509crl;
	}

}
