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
package eu.europa.esig.dss.enumerations;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Defines QC Type OID identifiers
 */
public interface QCType extends OidDescription {

    /** Logger */
    Logger LOG = LoggerFactory.getLogger(QCType.class);

    /** Defines a description for a type unknown by the current implementation */
    String UNKNOWN_TYPE = "type-unknown";

    /**
     * Returns a {@code QCType} by the given OID, if exists
     *
     * @param oid {@link String} to get {@link QCType} for
     * @return {@link QCType} if exists, NULL otherwise
     */
    static QCType fromOid(String oid) {
        for (QCType type : QCTypeEnum.values()) {
            if (type.getOid().equals(oid)) {
                return type;
            }
        }

        LOG.debug("Not supported QcType : '{}'", oid);
        return new QCType() {
            @Override
            public String getDescription() { return UNKNOWN_TYPE; }
            @Override
            public String getOid() { return oid; }
        };
    }

}
