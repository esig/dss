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
package eu.europa.esig.dss.eaa.sd.jwt.creation;

import eu.europa.esig.dss.eaa.common.creation.TokenStatusList;
import eu.europa.esig.dss.model.x509.CertificateToken;

import java.util.Objects;

/**
 * Parameter for an EAA Status definition according to the requirements present in
 * ETSI TS 119 472-1 "5.2.10 EAA status service".
 *
 */
public class ETSITokenStatusList extends TokenStatusList {

    private static final long serialVersionUID = 1803354941202111900L;

    /** Type of the EAA status */
    private final String type;

    /** Purpose of the EAA status */
    private final String purpose;

    /**
     * Default constructor
     *
     * @param type {@link String}
     * @param purpose {@link String}
     * @param index integer
     * @param uri {@link String}
     */
    public ETSITokenStatusList(String type, String purpose, int index, String uri) {
        this(type, purpose, index, uri, null);
    }

    /**
     * Constructor with certificate
     *
     * @param type {@link String}
     * @param purpose {@link String}
     * @param index integer
     * @param uri {@link String}
     * @param certificateToken {@link CertificateToken}
     */
    public ETSITokenStatusList(String type, String purpose, int index, String uri, CertificateToken certificateToken) {
        super(index, uri, certificateToken);
        Objects.requireNonNull(type, "Type cannot be null!");
        Objects.requireNonNull(purpose, "Purpose cannot be null!");

        this.type = type;
        this.purpose = purpose;
    }

    /**
     * Gets type of the EAA status list
     *
     * @return {@link String}
     */
    public String getType() {
        return type;
    }

    /**
     * Gets purpose of the EAA status list
     *
     * @return {@link String}
     */
    public String getPurpose() {
        return purpose;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;
        if (!super.equals(object)) return false;

        ETSITokenStatusList that = (ETSITokenStatusList) object;
        return Objects.equals(type, that.type)
                && Objects.equals(purpose, that.purpose);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Objects.hashCode(type);
        result = 31 * result + Objects.hashCode(purpose);
        return result;
    }

    @Override
    public String toString() {
        return "ETSIEAAStatusList [" +
                "type='" + type + '\'' +
                ", purpose='" + purpose + '\'' +
                "] " + super.toString();
    }

}
