/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import java.util.List;
import java.util.Map;

/**
 * Represents the DSS dictionary
 */
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
	 * @return a map of identifiers and {@link CertificateToken}s
	 */
	Map<Long, CertificateToken> getCERTs();

	/**
	 * Returns a list of VRI dictionaries
	 * 
	 * @return a list of {@link PdfVRIDict}s
	 */
	List<PdfVRIDict> getVRIs();

}
