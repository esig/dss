package eu.europa.esig.dss.tsl;

import java.util.List;

import eu.europa.esig.dss.x509.CertificateToken;

public interface TSLPointer {

	String getTerritory();

	String getMimeType();

	String getXmlUrl();

	List<CertificateToken> getPotentialSigners();

}
