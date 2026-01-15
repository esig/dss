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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Path;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.xpath.XPathUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;

class XAdESLevelAv2Test extends XAdESLevelATest {

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        XAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setEn319132(true);
        return signatureParameters;
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        Document document = DomUtils.buildDOM(byteArray);
        NodeList signaturesList = DSSXMLUtils.getAllSignaturesExceptCounterSignatures(document);
        assertEquals(1, signaturesList.getLength());

        XAdES132Path paths = new XAdES132Path();

        Node signature = signaturesList.item(0);
        NodeList signingCertificateList = XPathUtils.getNodeList(signature, paths.getSigningCertificateChildren());
        assertEquals(0, signingCertificateList.getLength());

        NodeList signingCertificateV2List = XPathUtils.getNodeList(signature, paths.getSigningCertificateV2Children());
        assertEquals(1, signingCertificateV2List.getLength());

        NodeList completeCertificateRefsList = XPathUtils.getNodeList(signature, paths.getCompleteCertificateRefsPath());
        assertEquals(0, completeCertificateRefsList.getLength());

        NodeList completeCertificateRefsV2List = XPathUtils.getNodeList(signature, paths.getCompleteCertificateRefsV2Path());
        assertEquals(1, completeCertificateRefsV2List.getLength());

        NodeList completeRevocationRefsList = XPathUtils.getNodeList(signature, paths.getCompleteRevocationRefsPath());
        assertEquals(1, completeRevocationRefsList.getLength());

        NodeList sigAndRefsTimeStampList = XPathUtils.getNodeList(signature, paths.getSigAndRefsTimestampPath());
        assertEquals(0, sigAndRefsTimeStampList.getLength());

        NodeList sigAndRefsTimeStampV2List = XPathUtils.getNodeList(signature, paths.getSigAndRefsTimestampV2Path());
        assertEquals(1, sigAndRefsTimeStampV2List.getLength());

        NodeList certificateValuesList = XPathUtils.getNodeList(signature, paths.getCertificateValuesPath());
        assertEquals(1, certificateValuesList.getLength());

        NodeList revocationValuesList = XPathUtils.getNodeList(signature, paths.getRevocationValuesPath());
        assertEquals(1, revocationValuesList.getLength());

        NodeList archiveTimestampList = XPathUtils.getNodeList(signature, paths.getArchiveTimestampPath());
        assertEquals(1, archiveTimestampList.getLength());
    }

}
