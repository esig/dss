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
package eu.europa.esig.dss.tsl.function.converter;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.tsl.Condition;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.tsl.dto.condition.CertSubjectDNAttributeCondition;
import eu.europa.esig.dss.tsl.dto.condition.CompositeCondition;
import eu.europa.esig.dss.tsl.dto.condition.ExtendedKeyUsageCondition;
import eu.europa.esig.dss.tsl.dto.condition.KeyUsageCondition;
import eu.europa.esig.dss.tsl.dto.condition.PolicyIdCondition;
import eu.europa.esig.dss.tsl.dto.condition.QCStatementCondition;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.enumerations.Assert;
import eu.europa.esig.trustedlist.jaxb.ecc.CriteriaListType;
import eu.europa.esig.trustedlist.jaxb.ecc.KeyUsageBitType;
import eu.europa.esig.trustedlist.jaxb.ecc.KeyUsageType;
import eu.europa.esig.trustedlist.jaxb.ecc.PoliciesListType;
import eu.europa.esig.trustedlist.jaxb.mra.QcStatementInfoType;
import eu.europa.esig.trustedlist.jaxb.mra.QcStatementListType;
import eu.europa.esig.trustedlist.jaxb.mra.QcStatementType;
import eu.europa.esig.trustedlist.jaxb.tslx.CertSubjectDNAttributeType;
import eu.europa.esig.trustedlist.jaxb.tslx.ExtendedKeyUsageType;
import eu.europa.esig.xades.jaxb.xades132.IdentifierType;
import eu.europa.esig.xades.jaxb.xades132.ObjectIdentifierType;
import jakarta.xml.bind.JAXBElement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * This class is used to convert a list of {@code CriteriaListType} to {@code Condition}
 *
 */
public class CriteriaListConverter implements Function<CriteriaListType, Condition> {

	private static final Logger LOG = LoggerFactory.getLogger(CriteriaListConverter.class);

	/**
	 * Default constructor
	 */
	public CriteriaListConverter() {
		// empty
	}

	@Override
	public Condition apply(CriteriaListType criteriaList) {
		Assert matchingCriteriaIndicator = criteriaList.getAssert();
		CompositeCondition condition = new CompositeCondition(matchingCriteriaIndicator);

		addKeyUsageConditionsIfPresent(criteriaList.getKeyUsage(), condition);
		addPolicyIdConditionsIfPresent(criteriaList.getPolicySet(), condition);
		addOtherCriteriaListConditionsIfPresent(criteriaList.getOtherCriteriaList(), condition);
		addCriteriaListConditionsIfPresent(criteriaList.getCriteriaList(), condition);

		return condition;
	}

	private void addKeyUsageConditionsIfPresent(List<KeyUsageType> keyUsages, CompositeCondition criteriaCondition) {
		if (Utils.isCollectionNotEmpty(keyUsages)) {
			for (KeyUsageType keyUsageType : keyUsages) {
				CompositeCondition condition = new CompositeCondition();
				for (KeyUsageBitType keyUsageBit : keyUsageType.getKeyUsageBit()) {
					condition.addChild(new KeyUsageCondition(keyUsageBit.getName(), keyUsageBit.isValue()));
				}
				criteriaCondition.addChild(condition);
			}
		}
	}

	private void addPolicyIdConditionsIfPresent(List<PoliciesListType> policySet,
			CompositeCondition criteriaCondition) {
		if (Utils.isCollectionNotEmpty(policySet)) {
			for (PoliciesListType policiesListType : policySet) {
				CompositeCondition condition = new CompositeCondition();
				for (ObjectIdentifierType oidType : policiesListType.getPolicyIdentifier()) {
					IdentifierType identifier = oidType.getIdentifier();
					if (identifier != null) {
						String id = DSSUtils.getObjectIdentifierValue(identifier.getValue(), identifier.getQualifier());
						if (Utils.isStringNotEmpty(id)) {
							condition.addChild(new PolicyIdCondition(id));
						}
					}
				}
				criteriaCondition.addChild(condition);
			}
		}
	}

	private String getOID(IdentifierType identifier) {
		String id = identifier.getValue();
		// ES TSL : <ns4:Identifier
		// Qualifier="OIDAsURN">urn:oid:1.3.6.1.4.1.36035.1.3.1</ns4:Identifier>
		if (DSSUtils.isUrnOid(id)) {
			id = DSSUtils.getOidCode(id);
		}
		return id;
	}

	/**
	 * ETSI TS 119 612 V1.1.1 / 5.5.9.2.2.3
	 * 
	 * @param otherCriteriaList {@link eu.europa.esig.xades.jaxb.xades132.AnyType}
	 * @param condition {@link CompositeCondition}
	 */
	private void addOtherCriteriaListConditionsIfPresent(eu.europa.esig.xades.jaxb.xades132.AnyType otherCriteriaList,
			CompositeCondition condition) {
		if (otherCriteriaList != null && Utils.isCollectionNotEmpty(otherCriteriaList.getContent())) {
			for (Object content : otherCriteriaList.getContent()) {
				if (content instanceof JAXBElement) {
					JAXBElement<?> jaxbElement = (JAXBElement<?>) content;
					Object objectValue = jaxbElement.getValue();
					if (objectValue instanceof CertSubjectDNAttributeType) {
						CertSubjectDNAttributeType certSubDNAttr = (CertSubjectDNAttributeType) objectValue;
						condition.addChild(
								new CertSubjectDNAttributeCondition(extractOids(certSubDNAttr.getAttributeOID())));

					} else if (objectValue instanceof ExtendedKeyUsageType) {
						ExtendedKeyUsageType extendedKeyUsage = (ExtendedKeyUsageType) objectValue;
						condition.addChild(
								new ExtendedKeyUsageCondition(extractOids(extendedKeyUsage.getKeyPurposeId())));

					} else if (objectValue instanceof QcStatementListType) {
						QcStatementListType qcStatementList = (QcStatementListType) objectValue;
						CompositeCondition composite = new CompositeCondition(Assert.ALL);
						List<QcStatementType> qcStatement = qcStatementList.getQcStatement();
						for (QcStatementType qcStatementType : qcStatement) {
							IdentifierType qcStatementIdentifier = qcStatementType.getQcStatementId().getIdentifier();
							String oid = DSSUtils.getObjectIdentifierValue(qcStatementIdentifier.getValue(), qcStatementIdentifier.getQualifier());
							String legislation = null;
							String type = null;

							QcStatementInfoType qcStatementInfo = qcStatementType.getQcStatementInfo();
							if (qcStatementInfo != null) {
								legislation = qcStatementInfo.getQcCClegislation();
								ObjectIdentifierType qcType = qcStatementInfo.getQcType();
								if (qcType != null) {
									IdentifierType qcTypeIdentifier = qcType.getIdentifier();
									String id = DSSUtils.getObjectIdentifierValue(qcTypeIdentifier.getValue(), qcTypeIdentifier.getQualifier());
									if (Utils.isStringNotEmpty(id)) {
										type = id;
									}
								}
							}

							composite.addChild(new QCStatementCondition(oid, type, legislation));
						}

						condition.addChild(composite);

					} else {
						throw new DSSException("Unsupported OtherCriteriaList");
					}
				}
			}
		}
	}

	private List<String> extractOids(List<ObjectIdentifierType> oits) {
		List<String> oids = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(oits)) {
			for (ObjectIdentifierType objectIdentifierType : oits) {
				IdentifierType identifier = objectIdentifierType.getIdentifier();
				if (identifier != null) {
					String id = DSSUtils.getObjectIdentifierValue(identifier.getValue(), identifier.getQualifier());
					if (Utils.isStringNotEmpty(id)) {
						if (DSSUtils.isOidCode(id)) {
							oids.add(id);
						} else {
							LOG.warn("The obtained value is not OID : '{}'!", id);
						}
					}
				}
			}
		}
		return oids;
	}

	private void addCriteriaListConditionsIfPresent(List<CriteriaListType> criteriaList, CompositeCondition condition) {
		if (Utils.isCollectionNotEmpty(criteriaList)) {
			for (CriteriaListType criteriaListType : criteriaList) {
				condition.addChild(apply(criteriaListType));
			}
		}
	}

}
