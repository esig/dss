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
package eu.europa.esig.dss.tsl.dto.condition;


import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.Condition;

import java.util.Objects;

/**
 * Condition based on the certificate key usage
 */
public class KeyUsageCondition implements Condition {

	private static final long serialVersionUID = -5078159553328523044L;

	/** Key usage bit to be checked */
	private final KeyUsageBit bit;

	/** The bit value of the key to be checked */
	private final boolean value;

	/**
	 * Constructs a new KeyUsageCondition.
	 *
	 * @param bit
	 *            the key usage
	 * @param value
	 *            the required value of the key usage bit
	 */
	public KeyUsageCondition(final KeyUsageBit bit, final boolean value) {
		Objects.requireNonNull(bit, "key usage");
		this.bit = bit;
		this.value = value;
	}

	/**
	 * Constructs a new KeyUsageCondition.
	 *
	 * @param usage
	 *            the key usage
	 * @param value
	 *            the required value of the key usage bit
	 */
	public KeyUsageCondition(final String usage, final boolean value) {
		this(KeyUsageBit.valueOf(usage), value);
	}

    /**
     * Returns the key usage to be checked.
     * 
     * @return never {@code null}
     */
    public final KeyUsageBit getBit() {
        return bit;
    }
    
    /**
     * Returns the required bit value of the key usage to be checked.
     * 
     * @return the required bit value of the key usage to be checked
     */
    public final boolean getValue() {
        return value;
    }

	@Override
	public boolean check(final CertificateToken certificateToken) {
		final boolean keyUsage = certificateToken.checkKeyUsage(bit);
		return keyUsage == value;
	}

	@Override
	public String toString(String indent) {
		if (indent == null) {
			indent = "";
		}
		StringBuilder builder = new StringBuilder();
		builder.append(indent).append("KeyUsageCondition: ").append(bit.name()).append('=').append(value).append('\n');
		return builder.toString();
	}

	@Override
	public String toString() {
		return toString("");
	}

}
