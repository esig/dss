package eu.europa.esig.dss.tsl.function.converter;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.tsl.dto.condition.CertSubjectDNAttributeCondition;
import eu.europa.esig.dss.tsl.dto.condition.CompositeCondition;
import eu.europa.esig.dss.tsl.dto.condition.ExtendedKeyUsageCondition;
import eu.europa.esig.dss.tsl.dto.condition.KeyUsageCondition;
import eu.europa.esig.dss.tsl.dto.condition.PolicyIdCondition;
import eu.europa.esig.dss.tsl.dto.condition.QCStatementCondition;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.enums.Assert;
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

import javax.xml.bind.JAXBElement;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

public class CriteriaListTypeConverter implements Function<CriteriaListType, Condition> {

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
					String id = identifier.getValue();

					// ES TSL : <ns4:Identifier
					// Qualifier="OIDAsURN">urn:oid:1.3.6.1.4.1.36035.1.3.1</ns4:Identifier>
					if (id.indexOf(':') >= 0) {
						id = id.substring(id.lastIndexOf(':') + 1);
					}

					condition.addChild(new PolicyIdCondition(id));
				}
				criteriaCondition.addChild(condition);
			}
		}
	}

	/**
	 * ETSI TS 119 612 V1.1.1 / 5.5.9.2.2.3
	 * 
	 * @param otherCriteriaList
	 * @param condition
	 */
	@SuppressWarnings("rawtypes")
	private void addOtherCriteriaListConditionsIfPresent(eu.europa.esig.xades.jaxb.xades132.AnyType otherCriteriaList,
			CompositeCondition condition) {
		if (otherCriteriaList != null && Utils.isCollectionNotEmpty(otherCriteriaList.getContent())) {
			for (Object content : otherCriteriaList.getContent()) {
				if (content instanceof JAXBElement) {
					JAXBElement jaxbElement = (JAXBElement) content;
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
							String oid = null;
							String legislation = null;
							String type = null;

							oid = qcStatementType.getQcStatementId().getIdentifier().getValue();
							QcStatementInfoType qcStatementInfo = qcStatementType.getQcStatementInfo();
							if (qcStatementInfo != null) {
								legislation = qcStatementInfo.getQcCClegislation();
								ObjectIdentifierType qcType = qcStatementInfo.getQcType();
								if (qcType != null) {
									type = qcType.getIdentifier().getValue();
								}
							}

							composite.addChild(new QCStatementCondition(
									DSSUtils.getOidCode(oid), DSSUtils.getOidCode(type), legislation));
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
				oids.add(objectIdentifierType.getIdentifier().getValue());
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
