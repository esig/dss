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

package eu.europa.ec.markt.dss.validation102853.condition;

import eu.europa.ec.markt.dss.validation102853.CertificateToken;

/**
 * Test if the certificate has a Key usage
 *
 * @version $Revision: 946 $ - $Date: 2011-06-06 17:15:14 +0200 (Mon, 06 Jun 2011) $
 */

public class KeyUsageCondition extends Condition {

    /**
     * KeyUsage bit values
     *
     * <p>
     * DISCLAIMER: Project owner DG-MARKT.
     *
     * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
     * @version $Revision: 946 $ - $Date: 2011-06-06 17:15:14 +0200 (Mon, 06 Jun 2011) $
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
