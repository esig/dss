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

import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
import eu.europa.esig.dss.enumerations.QCTypeEnum;
import eu.europa.esig.dss.model.tsl.Condition;
import eu.europa.esig.dss.tsl.dto.condition.CertSubjectDNAttributeCondition;
import eu.europa.esig.dss.tsl.dto.condition.CompositeCondition;
import eu.europa.esig.dss.tsl.dto.condition.ExtendedKeyUsageCondition;
import eu.europa.esig.dss.tsl.dto.condition.KeyUsageCondition;
import eu.europa.esig.dss.tsl.dto.condition.PolicyIdCondition;
import eu.europa.esig.dss.tsl.dto.condition.QCStatementCondition;
import eu.europa.esig.trustedlist.jaxb.ecc.CriteriaListType;
import eu.europa.esig.trustedlist.jaxb.ecc.KeyUsageBitType;
import eu.europa.esig.trustedlist.jaxb.ecc.KeyUsageType;
import eu.europa.esig.trustedlist.jaxb.ecc.PoliciesListType;
import eu.europa.esig.trustedlist.jaxb.mra.QcStatementInfoType;
import eu.europa.esig.trustedlist.jaxb.mra.QcStatementListType;
import eu.europa.esig.trustedlist.jaxb.mra.QcStatementType;
import eu.europa.esig.trustedlist.jaxb.tslx.CertSubjectDNAttributeType;
import eu.europa.esig.trustedlist.jaxb.tslx.ExtendedKeyUsageType;
import eu.europa.esig.xades.jaxb.xades132.AnyType;
import eu.europa.esig.xades.jaxb.xades132.IdentifierType;
import eu.europa.esig.xades.jaxb.xades132.ObjectIdentifierType;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.junit.jupiter.api.Test;

import jakarta.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CriteriaListConverterTest {

    @Test
    void extractKeyUsageTest() {
        CriteriaListType criteriaListType = new CriteriaListType();

        KeyUsageType keyUsageType = new KeyUsageType();

        KeyUsageBitType nonRepudiationBit = new KeyUsageBitType();
        nonRepudiationBit.setValue(true);
        nonRepudiationBit.setName(KeyUsageBit.NON_REPUDIATION);
        keyUsageType.getKeyUsageBit().add(nonRepudiationBit);

        KeyUsageBitType decipherOnlyBit = new KeyUsageBitType();
        decipherOnlyBit.setValue(false);
        decipherOnlyBit.setName(KeyUsageBit.DECIPHER_ONLY);
        keyUsageType.getKeyUsageBit().add(decipherOnlyBit);

        criteriaListType.getKeyUsage().add(keyUsageType);

        CriteriaListConverter criteriaListConverter = new CriteriaListConverter();
        Condition condition = criteriaListConverter.apply(criteriaListType);
        assertTrue(condition instanceof CompositeCondition);

        CompositeCondition compositeCondition = (CompositeCondition) condition;
        List<Condition> children = compositeCondition.getChildren();
        assertEquals(1, children.size());
        assertTrue(children.get(0) instanceof CompositeCondition);

        compositeCondition = (CompositeCondition) children.get(0);
        children = compositeCondition.getChildren();
        assertEquals(2, children.size());

        assertTrue(children.get(0) instanceof KeyUsageCondition);
        assertEquals(KeyUsageBit.NON_REPUDIATION, ((KeyUsageCondition) children.get(0)).getBit());
        assertTrue(((KeyUsageCondition) children.get(0)).getValue());

        assertTrue(children.get(1) instanceof KeyUsageCondition);
        assertEquals(KeyUsageBit.DECIPHER_ONLY, ((KeyUsageCondition) children.get(1)).getBit());
        assertFalse(((KeyUsageCondition) children.get(1)).getValue());
    }

    @Test
    void extractPolicyIdTest() {
        CriteriaListType criteriaListType = new CriteriaListType();

        PoliciesListType policiesListType = new PoliciesListType();

        ObjectIdentifierType uriObjectIdentifier = new ObjectIdentifierType();
        IdentifierType uriIdentifier = new IdentifierType();
        uriIdentifier.setValue("5.6.8.9");
        uriObjectIdentifier.setIdentifier(uriIdentifier);
        policiesListType.getPolicyIdentifier().add(uriObjectIdentifier);

        ObjectIdentifierType oidObjectIdentifier = new ObjectIdentifierType();
        IdentifierType oidIdentifier = new IdentifierType();
        oidIdentifier.setValue("urn:oid:1.2.5.6");
        oidIdentifier.setQualifier(ObjectIdentifierQualifier.OID_AS_URN);
        oidObjectIdentifier.setIdentifier(oidIdentifier);
        policiesListType.getPolicyIdentifier().add(oidObjectIdentifier);

        ObjectIdentifierType oidNoQualifierObjectIdentifier = new ObjectIdentifierType();
        IdentifierType oidNoQualifierIdentifier = new IdentifierType();
        oidNoQualifierIdentifier.setValue("urn:oid:10.55.11.23");
        oidNoQualifierObjectIdentifier.setIdentifier(oidNoQualifierIdentifier);
        policiesListType.getPolicyIdentifier().add(oidNoQualifierObjectIdentifier);

        criteriaListType.getPolicySet().add(policiesListType);

        CriteriaListConverter criteriaListConverter = new CriteriaListConverter();
        Condition condition = criteriaListConverter.apply(criteriaListType);
        assertTrue(condition instanceof CompositeCondition);

        CompositeCondition compositeCondition = (CompositeCondition) condition;
        List<Condition> children = compositeCondition.getChildren();
        assertEquals(1, children.size());
        assertTrue(children.get(0) instanceof CompositeCondition);

        compositeCondition = (CompositeCondition) children.get(0);
        children = compositeCondition.getChildren();
        assertEquals(3, children.size());

        assertTrue(children.get(0) instanceof PolicyIdCondition);
        assertEquals("5.6.8.9", ((PolicyIdCondition) children.get(0)).getPolicyOid());

        assertTrue(children.get(1) instanceof PolicyIdCondition);
        assertEquals("1.2.5.6", ((PolicyIdCondition) children.get(1)).getPolicyOid());

        assertTrue(children.get(2) instanceof PolicyIdCondition);
        assertEquals("10.55.11.23", ((PolicyIdCondition) children.get(2)).getPolicyOid());
    }

    @Test
    void extractCertSubjectDNAttrTest() {
        CriteriaListType criteriaListType = new CriteriaListType();

        CertSubjectDNAttributeType certSubjectDNAttributeType = new CertSubjectDNAttributeType();

        ObjectIdentifierType uriObjectIdentifier = new ObjectIdentifierType();
        IdentifierType uriIdentifier = new IdentifierType();
        uriIdentifier.setValue(BCStyle.CN.getId());
        uriObjectIdentifier.setIdentifier(uriIdentifier);
        certSubjectDNAttributeType.getAttributeOID().add(uriObjectIdentifier);

        ObjectIdentifierType oidObjectIdentifier = new ObjectIdentifierType();
        IdentifierType oidIdentifier = new IdentifierType();
        oidIdentifier.setValue("urn:oid:" + BCStyle.ORGANIZATION_IDENTIFIER.getId());
        oidIdentifier.setQualifier(ObjectIdentifierQualifier.OID_AS_URN);
        oidObjectIdentifier.setIdentifier(oidIdentifier);
        certSubjectDNAttributeType.getAttributeOID().add(oidObjectIdentifier);

        ObjectIdentifierType oidNoQualifierObjectIdentifier = new ObjectIdentifierType();
        IdentifierType oidNoQualifierIdentifier = new IdentifierType();
        oidNoQualifierIdentifier.setValue("urn:oid:" + BCStyle.PSEUDONYM.getId());
        oidNoQualifierObjectIdentifier.setIdentifier(oidNoQualifierIdentifier);
        certSubjectDNAttributeType.getAttributeOID().add(oidNoQualifierObjectIdentifier);

        AnyType anyType = new AnyType();
        anyType.getContent().add(new JAXBElement<>(new QName("CertSubjectDNAttribute"), CertSubjectDNAttributeType.class, certSubjectDNAttributeType));
        criteriaListType.setOtherCriteriaList(anyType);

        CriteriaListConverter criteriaListConverter = new CriteriaListConverter();
        Condition condition = criteriaListConverter.apply(criteriaListType);
        assertTrue(condition instanceof CompositeCondition);

        CompositeCondition compositeCondition = (CompositeCondition) condition;
        List<Condition> children = compositeCondition.getChildren();
        assertEquals(1, children.size());
        assertTrue(children.get(0) instanceof CertSubjectDNAttributeCondition);

        List<String> attributeOids = ((CertSubjectDNAttributeCondition) children.get(0)).getAttributeOids();
        assertEquals(3, attributeOids.size());
        assertEquals(BCStyle.CN.getId(), attributeOids.get(0));
        assertEquals(BCStyle.ORGANIZATION_IDENTIFIER.getId(), attributeOids.get(1));
        assertEquals(BCStyle.PSEUDONYM.getId(), attributeOids.get(2));
    }

    @Test
    void extractExtendedKeyUsageTest() {
        CriteriaListType criteriaListType = new CriteriaListType();

        ExtendedKeyUsageType extendedKeyUsageType = new ExtendedKeyUsageType();

        ObjectIdentifierType uriObjectIdentifier = new ObjectIdentifierType();
        IdentifierType uriIdentifier = new IdentifierType();
        uriIdentifier.setValue(ExtendedKeyUsage.OCSP_SIGNING.getOid());
        uriObjectIdentifier.setIdentifier(uriIdentifier);
        extendedKeyUsageType.getKeyPurposeId().add(uriObjectIdentifier);

        ObjectIdentifierType oidObjectIdentifier = new ObjectIdentifierType();
        IdentifierType oidIdentifier = new IdentifierType();
        oidIdentifier.setValue("urn:oid:" + ExtendedKeyUsage.TIMESTAMPING.getOid());
        oidIdentifier.setQualifier(ObjectIdentifierQualifier.OID_AS_URN);
        oidObjectIdentifier.setIdentifier(oidIdentifier);
        extendedKeyUsageType.getKeyPurposeId().add(oidObjectIdentifier);

        ObjectIdentifierType oidNoQualifierObjectIdentifier = new ObjectIdentifierType();
        IdentifierType oidNoQualifierIdentifier = new IdentifierType();
        oidNoQualifierIdentifier.setValue("urn:oid:" + ExtendedKeyUsage.CLIENT_AUTH.getOid());
        oidNoQualifierObjectIdentifier.setIdentifier(oidNoQualifierIdentifier);
        extendedKeyUsageType.getKeyPurposeId().add(oidNoQualifierObjectIdentifier);

        ObjectIdentifierType notOIDQualifierObjectIdentifier = new ObjectIdentifierType();
        IdentifierType notOIDQualifierIdentifier = new IdentifierType();
        notOIDQualifierIdentifier.setValue("hello-world");
        notOIDQualifierObjectIdentifier.setIdentifier(notOIDQualifierIdentifier);
        extendedKeyUsageType.getKeyPurposeId().add(notOIDQualifierObjectIdentifier);

        AnyType anyType = new AnyType();
        anyType.getContent().add(new JAXBElement<>(new QName("ExtendedKeyUsage"), ExtendedKeyUsageType.class, extendedKeyUsageType));
        criteriaListType.setOtherCriteriaList(anyType);

        CriteriaListConverter criteriaListConverter = new CriteriaListConverter();
        Condition condition = criteriaListConverter.apply(criteriaListType);
        assertTrue(condition instanceof CompositeCondition);

        CompositeCondition compositeCondition = (CompositeCondition) condition;
        List<Condition> children = compositeCondition.getChildren();
        assertEquals(1, children.size());
        assertTrue(children.get(0) instanceof ExtendedKeyUsageCondition);

        List<String> keyPurposeIds = ((ExtendedKeyUsageCondition) children.get(0)).getKeyPurposeIds();
        assertEquals(3, keyPurposeIds.size());
        assertEquals(ExtendedKeyUsage.OCSP_SIGNING.getOid(), keyPurposeIds.get(0));
        assertEquals(ExtendedKeyUsage.TIMESTAMPING.getOid(), keyPurposeIds.get(1));
        assertEquals(ExtendedKeyUsage.CLIENT_AUTH.getOid(), keyPurposeIds.get(2));
    }

    @Test
    void extractQcStatementTest() {
        CriteriaListType criteriaListType = new CriteriaListType();

        QcStatementListType qcStatementListType = new QcStatementListType();

        QcStatementType qcComplianceType = new QcStatementType();
        ObjectIdentifierType objectIdentifierType = new ObjectIdentifierType();
        IdentifierType uriIdentifier = new IdentifierType();
        uriIdentifier.setValue(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance.getId());
        objectIdentifierType.setIdentifier(uriIdentifier);
        qcComplianceType.setQcStatementId(objectIdentifierType);

        qcStatementListType.getQcStatement().add(qcComplianceType);

        QcStatementType qcTypeType = new QcStatementType();
        QcStatementInfoType qcStatementInfoType = new QcStatementInfoType();

        objectIdentifierType = new ObjectIdentifierType();
        uriIdentifier = new IdentifierType();
        uriIdentifier.setValue("urn:oid:" + ETSIQCObjectIdentifiers.id_etsi_qcs_QcType.getId());
        objectIdentifierType.setIdentifier(uriIdentifier);
        qcTypeType.setQcStatementId(objectIdentifierType);

        ObjectIdentifierType objectIdentifierQcType = new ObjectIdentifierType();
        IdentifierType uriQcTypeIdentifier = new IdentifierType();
        uriQcTypeIdentifier.setValue("urn:oid:" + QCTypeEnum.QCT_ESIGN.getOid());
        objectIdentifierQcType.setIdentifier(uriQcTypeIdentifier);
        qcStatementInfoType.setQcType(objectIdentifierQcType);

        qcTypeType.setQcStatementInfo(qcStatementInfoType);

        qcStatementListType.getQcStatement().add(qcTypeType);

        AnyType anyType = new AnyType();
        anyType.getContent().add(new JAXBElement<>(new QName("QcStatementSet"), QcStatementListType.class, qcStatementListType));
        criteriaListType.setOtherCriteriaList(anyType);

        CriteriaListConverter criteriaListConverter = new CriteriaListConverter();
        Condition condition = criteriaListConverter.apply(criteriaListType);
        assertTrue(condition instanceof CompositeCondition);

        CompositeCondition compositeCondition = (CompositeCondition) condition;
        List<Condition> children = compositeCondition.getChildren();
        assertEquals(1, children.size());
        assertTrue(children.get(0) instanceof CompositeCondition);

        compositeCondition = (CompositeCondition) children.get(0);
        children = compositeCondition.getChildren();
        assertEquals(2, children.size());

        assertTrue(children.get(0) instanceof QCStatementCondition);
        assertEquals(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance.getId(), ((QCStatementCondition) children.get(0)).getOid());

        assertTrue(children.get(1) instanceof QCStatementCondition);
        assertEquals(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType.getId(), ((QCStatementCondition) children.get(1)).getOid());
        assertEquals(QCTypeEnum.QCT_ESIGN.getOid(), ((QCStatementCondition) children.get(1)).getType());
    }

}
