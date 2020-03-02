package eu.europa.esig.dss.pdf;

import java.util.List;
import java.util.Map;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;

public interface PdfDssDict {
	
	/**
	 * Returns a map of uniques identifiers and CRL binaries
	 * 
	 * @return a map of identifiers and CRL binaries
	 */
	Map<Long, CRLBinary> getCRLs();

	/**
	 * Returns a map of unique identifiers and BasicOCSPResponses
	 * 
	 * @return a map of identifiers and {@link BasicOCSPResp}s
	 */
	Map<Long, BasicOCSPResp> getOCSPs();

	/**
	 * Returns a map of unique identifiers and Certificate Tokens
	 * 
	 * @return a map of indetifiers and {@link CertificateToken}s
	 */
	Map<Long, CertificateToken> getCERTs();

	/**
	 * Returns a list of VRI dictionaries
	 * 
	 * @return a list of {@link PdfVRIDict}s
	 */
	List<PdfVRIDict> getVRIs();

}
