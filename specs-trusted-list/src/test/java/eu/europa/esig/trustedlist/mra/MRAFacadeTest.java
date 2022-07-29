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
package eu.europa.esig.trustedlist.mra;

import eu.europa.esig.trustedlist.TrustedListFacade;
import eu.europa.esig.trustedlist.jaxb.mra.MutualRecognitionAgreementInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.AdditionalInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.AnyType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointersType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class MRAFacadeTest {

    @Test
    public void testLOTL() throws JAXBException, XMLStreamException, IOException, SAXException {
        marshallUnmarshall(new File("src/test/resources/lotl.xml"));
    }

    @Test
    public void testMRA_LOTL() throws JAXBException, XMLStreamException, IOException, SAXException {
        marshallUnmarshall(new File("src/test/resources/mra/mra-lotl.xml"));
    }

    @Test
    public void testMRA_BE() throws JAXBException, XMLStreamException, IOException, SAXException {
        marshallUnmarshall(new File("src/test/resources/mra/be-tl.xml"));
    }

    @Test
    public void testMRA_TC() throws JAXBException, XMLStreamException, IOException, SAXException {
        marshallUnmarshall(new File("src/test/resources/mra/tc-tl.xml"));
    }

    private void marshallUnmarshall(File file) throws JAXBException, XMLStreamException, IOException, SAXException {
        MRAFacade facade = MRAFacade.newFacade();

        TrustStatusListType trustStatusListType = facade.unmarshall(file);
        assertNotNull(trustStatusListType);

        String marshall = facade.marshall(trustStatusListType, true);
        assertNotNull(marshall);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testMRA_LOTL_extract() throws JAXBException, XMLStreamException, IOException, SAXException {
        TrustedListFacade facade = MRAFacade.newFacade();

        TrustStatusListType trustStatusListType = facade
                .unmarshall(new File("src/test/resources/mra/mra-lotl.xml"));
        assertNotNull(trustStatusListType);

        OtherTSLPointersType pointersToOtherTSL = trustStatusListType.getSchemeInformation().getPointersToOtherTSL();
        assertEquals(44, pointersToOtherTSL.getOtherTSLPointer().size());

        OtherTSLPointerType tcTL = pointersToOtherTSL.getOtherTSLPointer().get(pointersToOtherTSL.getOtherTSLPointer().size() - 1);

        AdditionalInformationType additionalInformation = tcTL.getAdditionalInformation();
        List<Serializable> textualInformationOrOtherInformation = additionalInformation
                .getTextualInformationOrOtherInformation();

        MutualRecognitionAgreementInformationType mraContent = null;

        Serializable serializable = textualInformationOrOtherInformation.get(5);
        if (serializable instanceof AnyType) {
            AnyType anyType = (AnyType) serializable;
            for (Object content : anyType.getContent()) {
                if (content instanceof JAXBElement) {
                    JAXBElement<MutualRecognitionAgreementInformationType> jaxbElement = (JAXBElement<MutualRecognitionAgreementInformationType>) content;
                    mraContent = jaxbElement.getValue();
                }
            }
        }
        assertNotNull(mraContent);
    }

}
