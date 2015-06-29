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
package eu.europa.esig.dss.tsl;

import eu.europa.esig.dss.x509.CertificateToken;

/**
 * Test if the certificate has a Key usage
 *
 *
 */

public class KeyUsageCondition extends Condition {

    /**
     * KeyUsage bit values
     *
     *
     *
     *
     *
     *
     */
    public static enum KeyUsageBit {

        digitalSignature(0), nonRepudiation(1), keyEncipherment(2), dataEncipherment(3), keyAgreement(4), keyCertSign(5), crlSign(6), encipherOnly(
              7), decipherOnly(8);

        int index;

        /**
         * The default constructor for KeyUsageCondition.KeyUsageBit.
         */
        private KeyUsageBit(final int index) {
            this.index = index;
        }
    }

    private final KeyUsageBit bit;
    private final boolean value;

    /**
     * The default constructor for KeyUsageCondition.
     *
     * @param bit
     */
    public KeyUsageCondition(final KeyUsageBit bit, final boolean value) {

        this.bit = bit;
        this.value = value;

    }

    /**
     * The default constructor for KeyUsageCondition.
     *
     * @param value
     */
    public KeyUsageCondition(final String usage, final boolean value) {

        this(KeyUsageBit.valueOf(usage), value);
    }

    /**
     * @return the bit
     */
    public KeyUsageBit getBit() {

        return bit;
    }

    /**
     * Checks the condition for the given certificate.
     *
     * @param certificateToken certificate to be checked
     * @return
     */
    @Override
    public boolean check(final CertificateToken certificateToken) {

        final boolean keyUsage = certificateToken.checkKeyUsage(bit.index);
        return keyUsage == value;
    }

    @Override
    public String toString(String indent) {

        if (indent == null) {
            indent = "";
        }
        StringBuilder builder = new StringBuilder();
        builder.append(indent).append("KeyUsageCondition: ").append(bit.name()).append("=").append(value).append('\n');
        return builder.toString();
    }

    @Override
    public String toString() {

        try {

            return toString("");
        } catch (Exception e) {

            return super.toString();
        }
    }
}
