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

/**
 * Contains a list of known and supported certificate approval statuss, based on the ETSI TS 119 602 profile definitions
 *
 */
public enum CertificateApprovalStatusEnum implements CertificateApprovalStatus {

    /** Represents a PID provider certificate, as defined in the ETSI TS 119 605, Annex C.1 */
    PID_PROVIDER("PID Provider", LoTETypeEnum.EUPIDProvidersList, LoTEServiceTypeIdentifierEnum.PID_ISSUANCE, null),

    /** Represents a certificate for PID revocation, according to the profile defined in ETSI TS 119 602, Annex C.1 */
    CERT_FOR_PID_REVOCATION("Certificate for PID Revocation", LoTETypeEnum.EUPIDProvidersList, LoTEServiceTypeIdentifierEnum.PID_REVOCATION, null),

    /** Represents a certificate for Wallet solution issuance, according to the profile defined in ETSI TS 119 602, Annex C.2 */
    CERT_FOR_WALLET_ISSUANCE("Certificate for Wallet Solution Issuance", LoTETypeEnum.EUWalletProvidersList, LoTEServiceTypeIdentifierEnum.WALLET_ISSUANCE, null),

    /** Represents a certificate for Wallet solution revocation, according to the profile defined in ETSI TS 119 602, Annex C.2 */
    CERT_FOR_WALLET_REVOCATION("Certificate for Wallet Solution Revocation", LoTETypeEnum.EUWalletProvidersList, LoTEServiceTypeIdentifierEnum.WALLET_REVOCATION, null),

    /** Represents a certificate for WRPAC issuance, according to the profile defined in ETSI TS 119 602, Annex F */
    CERT_FOR_WRPAC_ISSUANCE("Certificate for WRPAC Issuance", LoTETypeEnum.EUWRPACProvidersList, LoTEServiceTypeIdentifierEnum.WRPAC_ISSUANCE, null),

    /** Represents a certificate for WRPAC revocation, according to the profile defined in ETSI TS 119 602, Annex F */
    CERT_FOR_WRPAC_REVOCATION("Certificate for WRPAC Revocation", LoTETypeEnum.EUWRPACProvidersList, LoTEServiceTypeIdentifierEnum.WRPAC_REVOCATION, null),

    /** Represents a certificate for WRPRC issuance, according to the profile defined in ETSI TS 119 602, Annex G */
    CERT_FOR_WRPRC_ISSUANCE("Certificate for WRPRC Issuance", LoTETypeEnum.EUWRPRCProvidersList, LoTEServiceTypeIdentifierEnum.WRPRC_ISSUANCE, null),

    /** Represents a certificate for WRPRC revocation, according to the profile defined in ETSI TS 119 602, Annex G */
    CERT_FOR_WRPRC_REVOCATION("Certificate for WRPRC Revocation", LoTETypeEnum.EUWRPRCProvidersList, LoTEServiceTypeIdentifierEnum.WRPRC_REVOCATION, null),

    /** Represents a notified certificate for Pub-EAA issuance, according to the profile defined in ETSI TS 119 602, Annex H */
    NOTIFIED_CERT_FOR_PUB_EAA_ISSUANCE("Notified Certificate for Pub-EAA Issuance", LoTETypeEnum.EUPubEAAProvidersList, LoTEServiceTypeIdentifierEnum.PUB_EAA_ISSUANCE, LoTEServiceStatusEnum.PUB_EAA_PROVIDER_NOTIFIED),

    /** Represents a notified certificate for Pub-EAA revocation, according to the profile defined in ETSI TS 119 602, Annex H */
    NOTIFIED_CERT_FOR_PUB_EAA_REVOCATION("Notified Certificate for Pub-EAA Revocation", LoTETypeEnum.EUPubEAAProvidersList, LoTEServiceTypeIdentifierEnum.PUB_EAA_REVOCATION, LoTEServiceStatusEnum.PUB_EAA_PROVIDER_NOTIFIED),

    /** Represents a withdrawn certificate for Pub-EAA issuance, according to the profile defined in ETSI TS 119 602, Annex H */
    WITHDRAWN_CERT_FOR_PUB_EAA_ISSUANCE("Notified Certificate for Pub-EAA Issuance", LoTETypeEnum.EUPubEAAProvidersList, LoTEServiceTypeIdentifierEnum.PUB_EAA_ISSUANCE, LoTEServiceStatusEnum.PUB_EAA_PROVIDER_WITHDRAWN),

    /** Represents a withdrawn certificate for Pub-EAA revocation, according to the profile defined in ETSI TS 119 602, Annex H */
    WITHDRAWN_CERT_FOR_PUB_EAA_REVOCATION("Notified Certificate for Pub-EAA Revocation", LoTETypeEnum.EUPubEAAProvidersList, LoTEServiceTypeIdentifierEnum.PUB_EAA_REVOCATION, LoTEServiceStatusEnum.PUB_EAA_PROVIDER_WITHDRAWN),

    /** Represents a certificate for Register, according to the profile defined in ETSI TS 119 602, Annex G */
    CERT_FOR_REGISTER("Certificate for Register", LoTETypeEnum.EURegistrarsAndRegistersList, LoTEServiceTypeIdentifierEnum.REGISTER, null),

    /** Represents a certificate of unknown type (e.g. an error or conflict on validation) */
    CERT_FOR_UNKNOWN("Certificate for Unknown usage", null, null, null),

    /** Not applicable (e.g. no LoTE trust anchor reached) */
    NA("Not applicable", null, null, null);

    /** User-friendly certificate label */
    private final String label;

    /** The applicable List type */
    private final ListType listType;

    /** The applicable service type identifier */
    private final LoTEServiceTypeIdentifier sti;

    /** The applicable service status */
    private final LoTEServiceStatus status;

    /**
     * Default constructor
     *
     * @param label {@link String}
     * @param listType {@link ListType}
     * @param sti {@link LoTEServiceTypeIdentifier}
     * @param status {@link LoTEServiceStatus}
     */
    CertificateApprovalStatusEnum(final String label, final ListType listType, final LoTEServiceTypeIdentifier sti,
                                  final LoTEServiceStatus status) {
        this.label = label;
        this.listType = listType;
        this.sti = sti;
        this.status = status;
    }

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

}
