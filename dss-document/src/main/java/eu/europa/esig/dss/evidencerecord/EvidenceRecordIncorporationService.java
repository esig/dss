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
package eu.europa.esig.dss.evidencerecord;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableEvidenceRecordIncorporationParameters;

import java.io.Serializable;

/**
 * This interface provides common methods for incorporation of evidence records within existing signatures
 *
 * @param <ERP> implementation of format related parameters for evidence record incorporation
 */
public interface EvidenceRecordIncorporationService<ERP extends SerializableEvidenceRecordIncorporationParameters> extends Serializable {

    /**
     * Incorporates the Evidence Record as an unsigned property into the signature
     *
     * @param signatureDocument      {@link DSSDocument} containing the signature
     *                               to add the evidence record into
     * @param evidenceRecordDocument {@link DSSDocument} to add
     * @param parameters             {@link SerializableEvidenceRecordIncorporationParameters} providing configuration for
     *                               the evidence record incorporation
     * @return {@link DSSDocument} signature document with an incorporated evidence record
     */
     DSSDocument addSignatureEvidenceRecord(DSSDocument signatureDocument, DSSDocument evidenceRecordDocument,
                                            ERP parameters);

}
