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

package eu.europa.ec.markt.dss.validation102853.crl;

import java.io.Serializable;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;

/**
 * The validation of a certificate requires the access to some CRLs. This information can be found online, in a cache or even in
 * the signature itself. This interface provides an abstraction of a CRL data source.
 *
 * @version $Revision$ - $Date$
 */
public interface CRLSource extends Serializable {

	/**
	 * Finds the CRL(s) for the requested certificate. If found:<br />
	 * - the CRL's signature is checked;<br />
	 * - the key usage of the CRL's signing certificate is verified;<br />
	 * <p/>
	 * The most recent CRL is returned. If the parameter is <code>null</code> than <code>null</code> is returned.
	 *
	 * @param certificateToken the certificate token for which the CRL need to be found.
	 * @return {@code CRLToken}, null if not found.
	 * @throws DSSException
	 */
	CRLToken findCrl(final CertificateToken certificateToken) throws DSSException;
}
