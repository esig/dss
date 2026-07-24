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

public enum LoTEServiceTypeIdentifierEnum implements LoTEServiceTypeIdentifier {

    PID_ISSUANCE("http://uri.etsi.org/19602/SvcType/PID/Issuance", "PID Issuance"),

    PID_REVOCATION("http://uri.etsi.org/19602/SvcType/PID/Revocation", "PID Revocation"),

    WALLET_ISSUANCE("http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance" , "Wallet Solution Issuance"),

    WALLET_REVOCATION("http://uri.etsi.org/19602/SvcType/WalletSolution/Revocation" , "Wallet Solution Revocation"),

    WRPAC_ISSUANCE("http://uri.etsi.org/19602/SvcType/WRPAC/Issuance", "WRPAC Issuance"),

    WRPAC_REVOCATION("http://uri.etsi.org/19602/SvcType/WRPAC/Revocation", "WRPAC Revocation"),

    WRPRC_ISSUANCE("http://uri.etsi.org/19602/SvcType/WRPRC/Issuance", "WRPRC Issuance"),

    WRPRC_REVOCATION("http://uri.etsi.org/19602/SvcType/WRPRC/Revocation" , "WRPRC Revocation"),

    PUB_EAA_ISSUANCE("http://uri.etsi.org/19602/SvcType/PubEAA/Issuance", "Pub-EAA Issuance"),

    PUB_EAA_REVOCATION("http://uri.etsi.org/19602/SvcType/PubEAA/Revocation", "Pub-EAA Revocation"),

    REGISTER("http://uri.etsi.org/19602/SvcType/Register", "Register");

    /** Service Type Identifier URI */
    private final String stiUri;

    /** User-friendly label defining the certificate approval revocation type */
    private final String label;

    /**
     * Default constructor
     *
     * @param stiUri {@link String}
     * @param label {@link String}
     */
    LoTEServiceTypeIdentifierEnum(final String stiUri, final String label) {
        this.stiUri = stiUri;
        this.label = label;
    }

    @Override
    public String getUri() {
        return stiUri;
    }

    @Override
    public String getLabel() {
        return label;
    }

}
