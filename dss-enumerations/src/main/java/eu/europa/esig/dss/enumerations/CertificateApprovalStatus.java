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
package eu.europa.esig.dss.enumerations;

import eu.europa.esig.dss.enumerations.loader.LoTELoader;

import java.util.Objects;
import java.util.ServiceLoader;

/**
 * Represents a certificate approval status, e.g. in the context of EUDI Wallet
 * 
 */
public interface CertificateApprovalStatus {

    /**
     * Gets a list type URI of the List of Trusted Entities providing the certificates of the given usage
     *
     * @return {@link ListType}
     */
    ListType getListType();

    /**
     * Gets the ServiceTypeIdentifier related to the certificate approval status
     *
     * @return {@link LoTEServiceTypeIdentifier}
     */
    LoTEServiceTypeIdentifier getServiceTypeIdentifier();

    /**
     * Gets the ServiceStatus corresponding to the certificate approval status
     *
     * @return {@link LoTEServiceStatus}
     */
    LoTEServiceStatus getServiceStatus();

    /**
     * Gets user-friendly description of the certificate approval status
     *
     * @return {@link String}
     */
    String getLabel();

    /**
     * This method returns a {@code CertificateApprovalStatus} for the given URI
     *
     * @param label {@link String}
     * @return {@link CertificateApprovalStatus}
     */
    static CertificateApprovalStatus fromLabel(String label) {
        Objects.requireNonNull(label, "URI cannot be null!");

        for (LoTELoader loader : loaders()) {
            CertificateApprovalStatus certApprovalStatus = loader.certificateApprovalStatusFromLabel(label);
            if (certApprovalStatus != null) {
                return certApprovalStatus;
            }
        }
        return null;
    }

    /**
     * This method returns a {@code CertificateApprovalStatus} for the given definition
     *
     * @param listType {@link ListType}
     * @param sti {@link LoTEServiceTypeIdentifier}
     * @param status {@link LoTEServiceStatus}
     * @return {@link CertificateApprovalStatus}
     */
    static CertificateApprovalStatus fromDefinition(ListType listType, LoTEServiceTypeIdentifier sti, LoTEServiceStatus status) {
        for (LoTELoader loader : loaders()) {
            CertificateApprovalStatus certApprovalStatus = loader.certificateApprovalStatusFromDefinition(listType, sti, status);
            if (certApprovalStatus != null) {
                return certApprovalStatus;
            }
        }
        return null;
    }

    /**
     * This method creates a new {@code CertificateApprovalStatus} from the provided data
     *
     * @param label {@link String}
     * @param listType {@link ListType}
     * @param sti {@link LoTEServiceTypeIdentifier}
     * @param status {@link LoTEServiceStatus}
     * @return {@link CertificateApprovalStatus}
     */
    static CertificateApprovalStatus create(String label, ListType listType, LoTEServiceTypeIdentifier sti, LoTEServiceStatus status) {
        return new CertificateApprovalStatus() {
            @Override
            public ListType getListType() {
                return listType;
            }

            @Override
            public LoTEServiceTypeIdentifier getServiceTypeIdentifier() {
                return sti;
            }

            @Override
            public LoTEServiceStatus getServiceStatus() {
                return status;
            }

            @Override
            public String getLabel() {
                return label;
            }
        };
    }

    /**
     * This method loads available {@code LoTELoader}s using a ServiceLoader
     *
     * @return iterable of {@link LoTELoader}
     */
    static Iterable<LoTELoader> loaders() {
        return ServiceLoader.load(LoTELoader.class);
    }

}
