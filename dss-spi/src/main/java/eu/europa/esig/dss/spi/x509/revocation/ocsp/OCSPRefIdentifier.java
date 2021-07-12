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
package eu.europa.esig.dss.spi.x509.revocation.ocsp;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRefIdentifier;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * An identifier used for an OCSP token reference
 *
 */
public final class OCSPRefIdentifier extends RevocationRefIdentifier {

	private static final long serialVersionUID = 3113937346660525679L;

	/**
	 * Default constructor
	 *
	 * @param ocspRef {@link OCSPRef}
	 */
	protected OCSPRefIdentifier(OCSPRef ocspRef) {
		super(getDigest(ocspRef));
	}
	
	private static Digest getDigest(OCSPRef ocspRef) {
		if (ocspRef.getDigest() != null) {
			return ocspRef.getDigest();
		}
		
		byte[] bytes;
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); DataOutputStream dos = new DataOutputStream(baos)) {
			if (ocspRef.getProducedAt() != null) {
				dos.writeLong(ocspRef.getProducedAt().getTime());
			}
			ResponderId responderId = ocspRef.getResponderId();
			if (responderId != null) {
				if (responderId.getSki() != null) {
					dos.write(responderId.getSki());
				}
				if (responderId.getX500Principal() != null) {
					dos.writeChars(responderId.getX500Principal().toString());
				}
			}
			dos.flush();
			bytes = baos.toByteArray();
		} catch (IOException e) {
			throw new DSSException("Cannot build DSS ID for the OCSP Ref.", e);
		}
		return new Digest(DIGEST_ALGO, DSSUtils.digest(DIGEST_ALGO, bytes));
	}

}
