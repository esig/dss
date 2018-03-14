/*******************************************************************************
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
 ******************************************************************************/
package eu.europa.esig.dss.signature.policy;

/**
 * EnuRevReq  ::= ENUMERATED {
 *         clrCheck        (0),
 *                    -- Checks must be made against current CRLs
 *                    -- (or authority revocation lists)
 *         ocspCheck       (1),
 *                    -- The revocation status must be checked using
 *                    -- the Online Certificate Status Protocol (RFC 2450)
 *         bothCheck       (2),
 *                    -- Both CRL and OCSP checks must be carried out
 *         eitherCheck     (3),
 *                    -- At least one of CRL or OCSP checks must be
 *                    -- carried out
 *         noCheck         (4),
 *                    -- no check is mandated
 *         other           (5)
 *                    -- Other mechanism as defined by signature policy
 *                    -- extension
 *                                               }
 * @author davyd.santos
 *
 */
public enum EnuRevReq {
	crlCheck,
	ocspCheck,
	bothCheck,
	eitherCheck,
	noCheck,
	other;
}
