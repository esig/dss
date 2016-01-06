package eu.europa.esig.dss.validation.policy.bbb.util;

import java.util.ArrayList;

import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlUsedCertificates;

public class TestXmlUsedCertificates extends XmlUsedCertificates {

	public void addXmlCertificates(XmlCertificate cert) {
		if(certificate == null) {
			certificate = new ArrayList<XmlCertificate>();
		}
		certificate.add(cert);
	}
	
}
