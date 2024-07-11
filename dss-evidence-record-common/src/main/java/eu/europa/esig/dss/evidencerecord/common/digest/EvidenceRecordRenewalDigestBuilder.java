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
package eu.europa.esig.dss.evidencerecord.common.digest;

import eu.europa.esig.dss.model.Digest;

import java.util.List;

/**
 * Builds digest(s) required for a renewal of an evidence-record.
 * NOTE: Does not perform validation of the evidence record
 *
 */
public interface EvidenceRecordRenewalDigestBuilder {

    /**
     * This method builds digest for a time-stamp renewal
     *
     * @return {@link Digest}
     */
    Digest buildTimeStampRenewalDigest();

    /**
     * This method builds digest for a hash-tree renewal.
     * NOTE: the corresponding detached contents may be required to be provided
     *
     * @return a list of {@link Digest}s
     */
    List<Digest> buildHashTreeRenewalDigestGroup();

}
