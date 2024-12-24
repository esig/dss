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

import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;

import java.security.cert.CertificateParsingException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * This class is used to filter private key predicates based on the certificate ExtendedKeyUsage attribute value
 *
 */
public class ExtendedKeyUsageKeyEntryPredicate implements DSSKeyEntryPredicate {

    /**
     * Collection of extended key usage OID to be accepted.
     */
    private final Collection<String> extendedKeyUsageOIDs;

    /**
     * Default constructor with an array of {@code ExtendedKeyUsage}s to be accepted
     *
     * @param extendedKeyUsages array of {@link KeyUsageBit}s to be accepted
     */
    public ExtendedKeyUsageKeyEntryPredicate(ExtendedKeyUsage... extendedKeyUsages) {
        Objects.requireNonNull(extendedKeyUsages, "ExtendedKeyUsage cannot be null!");
        this.extendedKeyUsageOIDs = Arrays.stream(extendedKeyUsages).filter(Objects::nonNull).map(ExtendedKeyUsage::getOid).collect(Collectors.toSet());
    }

    /**
     * Constructor with an array of ExtendedKeyUsage OIDs to be accepted
     *
     * @param extendedKeyUsageOIDs array of {@link String}s to be accepted
     */
    public ExtendedKeyUsageKeyEntryPredicate(String... extendedKeyUsageOIDs) {
        Objects.requireNonNull(extendedKeyUsageOIDs, "ExtendedKeyUsage OIDs cannot be null!");
        this.extendedKeyUsageOIDs = Arrays.asList(extendedKeyUsageOIDs);
    }

    @Override
    public boolean test(DSSPrivateKeyEntry dssPrivateKeyEntry) {
        CertificateToken certificate = dssPrivateKeyEntry.getCertificate();
        if (certificate != null) {
            List<String> extendedKeyUsages = getExtendedKeyUsages(certificate);
            if (extendedKeyUsages != null && !extendedKeyUsages.isEmpty()) {
                for (String extendedKeyUsage : extendedKeyUsages) {
                    if (extendedKeyUsageOIDs.contains(extendedKeyUsage)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private List<String> getExtendedKeyUsages(CertificateToken certificateToken) {
        try {
            return certificateToken.getCertificate().getExtendedKeyUsage();
        } catch (CertificateParsingException e) {
            throw new DSSException(String.format("Unable to extract ExtendedKeyUsage from a certificate token. " +
                    "Reason : %s", e.getMessage()), e);
        }
    }

}
