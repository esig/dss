/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.ocsp;

import java.io.Serializable;

import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.OCSPToken;

/**
 * The validation of a certificate may require the use of OCSP information. Theses information can be provided by multiple sources
 * (the signature itself, online OCSP server, ...). This interface provides an abstraction for a source of OCSPResp
 *
 * @version $Revision$ - $Date$
 */

public interface OCSPSource extends Serializable {

	/**
	 * Gets an {@code OCSPToken} for the given certificate / issuer's certificate couple. The coherence between the response and the request is checked.
	 *
	 * @param certificateToken The {@code CertificateToken} for which the request is made
	 * @param certificatePool  The {@code CertificatePool} used to obtain the issuer of the OCSP
	 * @return {@code OCSPToken} containing information about the validity of the cert
	 */
	OCSPToken getOCSPToken(final CertificateToken certificateToken, final CertificatePool certificatePool);
}
