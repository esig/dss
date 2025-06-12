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
 * Defines an unsigned attribute type within a CAdES signature for incorporation of an evidence record
 * (i.e. internal vs external).
 *
 */
public enum EvidenceRecordIncorporationType {

    /**
     * Defines the internal-evidence-records attribute (clause 5.2) protecting the whole SignedData instance and
     * used in cases of attached signatures.
     */
    INTERNAL_EVIDENCE_RECORD,

    /**
     * Defines the external-evidence-records attribute (clause 5.3) also protecting the whole SignedData
     * instance not containing an eContent element within encapContentInfo (a detached signature), and the
     * external signed data.
     */
    EXTERNAL_EVIDENCE_RECORD

}
