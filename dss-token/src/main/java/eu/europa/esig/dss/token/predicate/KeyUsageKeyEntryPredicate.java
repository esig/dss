/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.token.predicate;

import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * This class is used to filter private key predicates based on the certificate KeyUsage attribute value
 *
 */
public class KeyUsageKeyEntryPredicate implements DSSKeyEntryPredicate {

    /** Collection of key usages to be accepted */
    private final Collection<KeyUsageBit> keyUsages;

    /**
     * Default constructor
     *
     * @param keyUsages array of {@link KeyUsageBit}s to be accepted
     */
    public KeyUsageKeyEntryPredicate(KeyUsageBit... keyUsages) {
        Objects.requireNonNull(keyUsages, "KeyUsage cannot be null!");
        this.keyUsages = Arrays.asList(keyUsages);
    }

    @Override
    public boolean test(DSSPrivateKeyEntry dssPrivateKeyEntry) {
        CertificateToken certificate = dssPrivateKeyEntry.getCertificate();
        if (certificate != null) {
            List<KeyUsageBit> keyUsageBits = certificate.getKeyUsageBits();
            if (keyUsageBits != null && !keyUsageBits.isEmpty()) {
                for (KeyUsageBit keyUsageBit : keyUsageBits) {
                    if (keyUsages.contains(keyUsageBit)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

}
