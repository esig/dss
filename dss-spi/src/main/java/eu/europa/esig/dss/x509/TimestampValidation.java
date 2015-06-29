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
package eu.europa.esig.dss.x509;

/**
 * This class holds the result of the timestamp's signature validation.
 *
 * To be valid the timestamp must be signed by the given certificate and the certificate must be the one referred to by the SigningCertificate attribute included in the hashed
 * attributes of the timestamp's signature. The certificate must also have the ExtendedKeyUsageExtension with only KeyPurposeId.id_kp_timeStamping and have been valid at the time
 * the timestamp was created.
 *
 *
 *
 *
 *
 */
public class TimestampValidation {

	private TimestampValidity timestampValidity;

	public TimestampValidation(final TimestampValidity timestampValidity) {

		this.timestampValidity = timestampValidity;
	}

	public boolean isValid() {
		return TimestampValidity.VALID.equals(timestampValidity);
	}

	public TimestampValidity getValidity() {
		return timestampValidity;
	}
}
