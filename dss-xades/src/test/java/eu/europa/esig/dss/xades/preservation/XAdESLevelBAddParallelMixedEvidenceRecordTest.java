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
package eu.europa.esig.dss.xades.preservation;

import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.xades.evidencerecord.XAdESEvidenceRecordIncorporationParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class XAdESLevelBAddParallelMixedEvidenceRecordTest extends AbstractXAdESAddEvidenceRecordTest {

    @Override
    protected DSSDocument getSignatureDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/incorporation/X-B-B.xml");
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return getXmlEvidenceRecordDocument();
    }

    protected DSSDocument getXmlEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/incorporation/evidence-record-X-B-B.xml");
    }

    protected DSSDocument getAsn1EvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/incorporation/evidence-record-X-B-B.ers");
    }

    @Override
    protected XAdESEvidenceRecordIncorporationParameters getEvidenceRecordIncorporationParameters() {
        XAdESEvidenceRecordIncorporationParameters parameters = super.getEvidenceRecordIncorporationParameters();
        parameters.setParallelEvidenceRecord(true);
        return parameters;
    }

    @Override
    protected EvidenceRecordTypeEnum getEvidenceRecordType() {
        return null;
    }

    @Test
    @Override
    public void addERAndValidate() {
        XAdESService service = getService();

        DSSDocument xmlERDoc = service.addSignatureEvidenceRecord(getSignatureDocument(), getXmlEvidenceRecordDocument(), getEvidenceRecordIncorporationParameters());

        Exception exception = assertThrows(IllegalInputException.class, () ->
                service.addSignatureEvidenceRecord(xmlERDoc, getAsn1EvidenceRecordDocument(), getEvidenceRecordIncorporationParameters()));
        assertEquals("The latest signature unsigned property contains evidence records other " +
                "than EvidenceRecord type specified in IETF RFC 4998. The incorporation of different evidence record " +
                "types within the same unsigned property is not supported.", exception.getMessage());

        DSSDocument asn1ERDoc = service.addSignatureEvidenceRecord(getSignatureDocument(), getAsn1EvidenceRecordDocument(), getEvidenceRecordIncorporationParameters());

        exception = assertThrows(IllegalInputException.class, () ->
                service.addSignatureEvidenceRecord(asn1ERDoc, getXmlEvidenceRecordDocument(), getEvidenceRecordIncorporationParameters()));
        assertEquals("The latest signature unsigned property contains evidence records other " +
                "than ers:EvidenceRecordType type specified in IETF RFC 6283. The incorporation of different evidence record " +
                "types within the same unsigned property is not supported.", exception.getMessage());
    }

}
