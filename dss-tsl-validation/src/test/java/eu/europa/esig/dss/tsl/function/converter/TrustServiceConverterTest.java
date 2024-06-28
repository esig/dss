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
package eu.europa.esig.dss.tsl.function.converter;

import eu.europa.esig.dss.model.tsl.ConditionForQualifiers;
import eu.europa.esig.dss.model.tsl.TrustService;
import eu.europa.esig.dss.model.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.model.timedependent.TimeDependentValues;
import eu.europa.esig.trustedlist.enums.Assert;
import eu.europa.esig.trustedlist.jaxb.ecc.CriteriaListType;
import eu.europa.esig.trustedlist.jaxb.ecc.QualificationElementType;
import eu.europa.esig.trustedlist.jaxb.ecc.QualificationsType;
import eu.europa.esig.trustedlist.jaxb.ecc.QualifierType;
import eu.europa.esig.trustedlist.jaxb.ecc.QualifiersType;
import eu.europa.esig.trustedlist.jaxb.tsl.ExtensionType;
import eu.europa.esig.trustedlist.jaxb.tsl.ExtensionsListType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import org.junit.jupiter.api.Test;

import jakarta.xml.bind.JAXBElement;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrustServiceConverterTest {

    @Test
    void extractQualifiersTest() throws Exception {
        TSPServiceType tspServiceType = new TSPServiceType();

        TSPServiceInformationType serviceInformation = new TSPServiceInformationType();

        GregorianCalendar c = new GregorianCalendar();
        c.setTime(new Date());
        serviceInformation.setStatusStartingTime(DatatypeFactory.newInstance().newXMLGregorianCalendar(c));

        tspServiceType.setServiceInformation(serviceInformation);
        ExtensionsListType serviceInformationExtensions = new ExtensionsListType();
        serviceInformation.setServiceInformationExtensions(serviceInformationExtensions);

        ExtensionType extensionOne = new ExtensionType();
        extensionOne.setCritical(true);
        extensionOne.getContent().add(createQualificationsWithQualifiers(Arrays.asList(
                Arrays.asList("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDManagedOnBehalf", "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD"),
                Arrays.asList("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement"))));

        serviceInformationExtensions.getExtension().add(extensionOne);

        ExtensionType extensionTwo = new ExtensionType();
        extensionTwo.setCritical(false);
        extensionTwo.getContent().add(createQualificationsWithQualifiers(Arrays.asList(
                Arrays.asList("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig"))));

        serviceInformationExtensions.getExtension().add(extensionTwo);

        TrustServiceConverter trustServiceConverter = new TrustServiceConverter();
        TrustService trustService = trustServiceConverter.apply(tspServiceType);
        TimeDependentValues<TrustServiceStatusAndInformationExtensions> statusAndInformationExtensions = trustService.getStatusAndInformationExtensions();
        Iterator<TrustServiceStatusAndInformationExtensions> iterator = statusAndInformationExtensions.iterator();
        int counter = 0;
        TrustServiceStatusAndInformationExtensions latest = null;
        while (iterator.hasNext()) {
            latest = iterator.next();
            ++counter;
        }
        assertEquals(1, counter);
        assertNotNull(latest);

        List<ConditionForQualifiers> conditionsForQualifiers = latest.getConditionsForQualifiers();
        assertEquals(3, conditionsForQualifiers.size());

        List<String> capturedUrls = new ArrayList<>();
        for (ConditionForQualifiers conditionForQualifiers : conditionsForQualifiers) {
            capturedUrls.addAll(conditionForQualifiers.getQualifiers());
        }
        assertEquals(4, capturedUrls.size());
        assertTrue(capturedUrls.contains("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDManagedOnBehalf"));
        assertTrue(capturedUrls.contains("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD"));
        assertTrue(capturedUrls.contains("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement"));
        assertTrue(capturedUrls.contains("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig"));

    }

    private JAXBElement createQualificationsWithQualifiers(List<List<String>> qualifiersUrls) {
        QualificationsType qualifications = new QualificationsType();
        for (List<String> qualificationElementUrls : qualifiersUrls) {
            QualificationElementType qualificationElement = new QualificationElementType();

            CriteriaListType criteriaList = new CriteriaListType();
            criteriaList.setAssert(Assert.ALL);
            qualificationElement.setCriteriaList(criteriaList);

            QualifiersType qualifiers = new QualifiersType();
            for (String qualifierUrl : qualificationElementUrls) {
                QualifierType qualifierType = new QualifierType();
                qualifierType.setUri(qualifierUrl);
                qualifiers.getQualifier().add(qualifierType);
            }
            qualificationElement.setQualifiers(qualifiers);
            qualifications.getQualificationElement().add(qualificationElement);
        }
        return new JAXBElement<>(new QName("Qualifications"), QualificationsType.class, qualifications);
    }

}
