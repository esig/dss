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
package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcCompliance;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQualifier;
import eu.europa.esig.dss.enumerations.AdditionalServiceInformation;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.QCTypeEnum;
import eu.europa.esig.dss.enumerations.ServiceQualification;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ServiceByCertificateTypeFilterTest {

    @Test
    void certForESigTest() {
        CertificateWrapper certificateWrapper = createCertificate(false, Collections.singletonList(QCTypeEnum.QCT_ESIGN));

        ServiceByCertificateTypeFilter filter = new ServiceByCertificateTypeFilter(certificateWrapper);
        assertTrue(filter.isAcceptable(createTrustServiceWrapper(
                Collections.singletonList(AdditionalServiceInformation.FOR_ESIGNATURES),
                Collections.emptyList()
        )));

        filter = new ServiceByCertificateTypeFilter(certificateWrapper);
        assertFalse(filter.isAcceptable(createTrustServiceWrapper(
                Collections.singletonList(AdditionalServiceInformation.FOR_ESEALS),
                Collections.emptyList()
        )));

        filter = new ServiceByCertificateTypeFilter(certificateWrapper);
        assertTrue(filter.isAcceptable(createTrustServiceWrapper(
                Arrays.asList(AdditionalServiceInformation.FOR_ESIGNATURES, AdditionalServiceInformation.FOR_ESEALS),
                Collections.emptyList()
        )));

        filter = new ServiceByCertificateTypeFilter(certificateWrapper);
        assertFalse(filter.isAcceptable(createTrustServiceWrapper(
                Arrays.asList(AdditionalServiceInformation.FOR_WEB_AUTHENTICATION, AdditionalServiceInformation.FOR_ESEALS),
                Collections.emptyList()
        )));
    }

    @Test
    void certForESigTLOverruleTest() {
        CertificateWrapper certificateWrapper = createCertificate(false, Collections.singletonList(QCTypeEnum.QCT_ESIGN));

        ServiceByCertificateTypeFilter filter = new ServiceByCertificateTypeFilter(certificateWrapper);
        assertTrue(filter.isAcceptable(createTrustServiceWrapper(
                Collections.singletonList(AdditionalServiceInformation.FOR_ESIGNATURES),
                Collections.singletonList(ServiceQualification.QC_FOR_ESIG)
        )));

        filter = new ServiceByCertificateTypeFilter(certificateWrapper);
        assertTrue(filter.isAcceptable(createTrustServiceWrapper(
                Collections.singletonList(AdditionalServiceInformation.FOR_ESIGNATURES),
                Collections.singletonList(ServiceQualification.QC_FOR_ESEAL)
        ))); // overruled

        filter = new ServiceByCertificateTypeFilter(certificateWrapper);
        assertTrue(filter.isAcceptable(createTrustServiceWrapper(
                Collections.singletonList(AdditionalServiceInformation.FOR_ESIGNATURES),
                Arrays.asList(ServiceQualification.QC_FOR_ESIG, ServiceQualification.QC_FOR_ESEAL)
        ))); // separate consistency check is executed

        filter = new ServiceByCertificateTypeFilter(certificateWrapper);
        assertFalse(filter.isAcceptable(createTrustServiceWrapper(
                Collections.singletonList(AdditionalServiceInformation.FOR_ESIGNATURES),
                Collections.singletonList(ServiceQualification.QC_FOR_LEGAL_PERSON)
        )));

        filter = new ServiceByCertificateTypeFilter(certificateWrapper);
        assertFalse(filter.isAcceptable(createTrustServiceWrapper(
                Collections.singletonList(AdditionalServiceInformation.FOR_ESEALS),
                Arrays.asList(ServiceQualification.QC_FOR_ESIG, ServiceQualification.QC_FOR_LEGAL_PERSON)
        )));
    }

    @Test
    void certForESealTLOverruleTest() {
        CertificateWrapper certificateWrapper = createCertificate(false, Collections.singletonList(QCTypeEnum.QCT_ESEAL));

        ServiceByCertificateTypeFilter filter = new ServiceByCertificateTypeFilter(certificateWrapper);
        assertTrue(filter.isAcceptable(createTrustServiceWrapper(
                Collections.singletonList(AdditionalServiceInformation.FOR_ESEALS),
                Collections.singletonList(ServiceQualification.QC_FOR_ESIG)
        ))); // overruled

        filter = new ServiceByCertificateTypeFilter(certificateWrapper);
        assertTrue(filter.isAcceptable(createTrustServiceWrapper(
                Collections.singletonList(AdditionalServiceInformation.FOR_ESEALS),
                Collections.singletonList(ServiceQualification.QC_FOR_ESEAL)
        )));

        filter = new ServiceByCertificateTypeFilter(certificateWrapper);
        assertTrue(filter.isAcceptable(createTrustServiceWrapper(
                Collections.singletonList(AdditionalServiceInformation.FOR_ESEALS),
                Arrays.asList(ServiceQualification.QC_FOR_ESIG, ServiceQualification.QC_FOR_ESEAL)
        ))); // separate consistency check is executed

        filter = new ServiceByCertificateTypeFilter(certificateWrapper);
        assertTrue(filter.isAcceptable(createTrustServiceWrapper(
                Collections.singletonList(AdditionalServiceInformation.FOR_ESEALS),
                Collections.singletonList(ServiceQualification.QC_FOR_LEGAL_PERSON)
        )));

        filter = new ServiceByCertificateTypeFilter(certificateWrapper);
        assertTrue(filter.isAcceptable(createTrustServiceWrapper(
                Collections.singletonList(AdditionalServiceInformation.FOR_ESEALS),
                Arrays.asList(ServiceQualification.QC_FOR_ESIG, ServiceQualification.QC_FOR_LEGAL_PERSON)
        )));
    }

    @Test
    void certForESigPreEIDASTest() {
        CertificateWrapper certificateWrapper = createCertificate(false, Collections.singletonList(QCTypeEnum.QCT_ESIGN), false);

        ServiceByCertificateTypeFilter filter = new ServiceByCertificateTypeFilter(certificateWrapper);
        assertTrue(filter.isAcceptable(createTrustServiceWrapper(
                Collections.singletonList(AdditionalServiceInformation.FOR_ESIGNATURES),
                Collections.emptyList()
        )));

        filter = new ServiceByCertificateTypeFilter(certificateWrapper);
        assertTrue(filter.isAcceptable(createTrustServiceWrapper(
                Collections.singletonList(AdditionalServiceInformation.FOR_ESEALS),
                Collections.emptyList()
        )));

        filter = new ServiceByCertificateTypeFilter(certificateWrapper);
        assertTrue(filter.isAcceptable(createTrustServiceWrapper(
                Arrays.asList(AdditionalServiceInformation.FOR_ESIGNATURES, AdditionalServiceInformation.FOR_ESEALS),
                Collections.emptyList()
        )));

        filter = new ServiceByCertificateTypeFilter(certificateWrapper);
        assertTrue(filter.isAcceptable(createTrustServiceWrapper(
                Arrays.asList(AdditionalServiceInformation.FOR_WEB_AUTHENTICATION, AdditionalServiceInformation.FOR_ESEALS),
                Collections.emptyList()
        )));
    }

    private CertificateWrapper createCertificate(boolean qcCompliance, List<QCTypeEnum> qcTypes) {
        return createCertificate(qcCompliance, qcTypes, true);
    }

    private CertificateWrapper createCertificate(boolean qcCompliance, List<QCTypeEnum> qcTypes, boolean postEIDAS) {
        XmlCertificate xmlCertificate = new XmlCertificate();
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        if (qcCompliance) {
            XmlQcCompliance xmlQcCompliance = new XmlQcCompliance();
            xmlQcCompliance.setPresent(qcCompliance);
            xmlQcStatements.setQcCompliance(xmlQcCompliance);
        }
        if (Utils.isCollectionNotEmpty(qcTypes)) {
            for (QCTypeEnum qcType : qcTypes) {
                XmlOID xmlOID = new XmlOID();
                xmlOID.setValue(qcType.getOid());
                xmlQcStatements.getQcTypes().add(xmlOID);
            }
        }
        if (postEIDAS) {
            xmlCertificate.setNotBefore(EIDASUtils.EIDAS_DATE);
        }
        xmlCertificate.getCertificateExtensions().add(xmlQcStatements);
        return new CertificateWrapper(xmlCertificate);
    }

    private TrustServiceWrapper createTrustServiceWrapper(List<AdditionalServiceInformation> asis, List<ServiceQualification> qualifiers) {
        TrustServiceWrapper trustServiceWrapper = new TrustServiceWrapper();

        if (Utils.isCollectionNotEmpty(asis)) {
            List<String> result = new ArrayList<>();
            for (AdditionalServiceInformation asi : asis) {
                result.add(asi.getUri());
            }
            trustServiceWrapper.setAdditionalServiceInfos(result);
        }
        if (Utils.isCollectionNotEmpty(qualifiers)) {
            List<XmlQualifier> result = new ArrayList<>();
            for (ServiceQualification qualifier : qualifiers) {
                XmlQualifier xmlQualifier = new XmlQualifier();
                xmlQualifier.setValue(qualifier.getUri());
                result.add(xmlQualifier);
            }
            trustServiceWrapper.setCapturedQualifiers(result);
        }

        return trustServiceWrapper;
    }

}
