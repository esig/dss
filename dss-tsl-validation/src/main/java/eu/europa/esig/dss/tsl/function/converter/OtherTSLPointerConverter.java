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

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.MRA;
import eu.europa.esig.dss.spi.tsl.OtherTSLPointer;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.mra.MutualRecognitionAgreementInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.AdditionalInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.AnyType;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityListType;
import eu.europa.esig.trustedlist.jaxb.tsl.InternationalNamesType;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIListType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceDigitalIdentityListType;

import javax.xml.bind.JAXBElement;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * The class is used to convert {@code OtherTSLPointerType} to {@code OtherTSLPointer}
 *
 */
public class OtherTSLPointerConverter implements Function<OtherTSLPointerType, OtherTSLPointer> {

	private static final String SCHEME_TERRITORY = "SchemeTerritory";

	private static final String TSL_TYPE = "TSLType";

	private static final String MIME_TYPE = "MimeType";

	private static final String SCHEME_OPERATOR_NAME = "SchemeOperatorName";

	private static final String SCHEME_TYPE_COMMUNITY_RULES = "SchemeTypeCommunityRules";

	private static final String MRA = "MutualRecognitionAgreementInformation";

	/** Defines whether MRA shall be extracted */
	private boolean mraSupport;

	/**
	 * Default constructor to instantiate an empty object
	 */
	public OtherTSLPointerConverter() {
		// empty
	}

	/**
	 * Constructor with a parameter to define the MRA support
	 *
	 * @param mraSupport defines whether MRA shall be extracted if present
	 */
	public OtherTSLPointerConverter(boolean mraSupport) {
		this.mraSupport = mraSupport;
	}

	@Override
	public OtherTSLPointer apply(OtherTSLPointerType original) {
		return new OtherTSLPointer.OtherTSLPointerBuilder()
				.setSdiCertificates(getCertificates(original.getServiceDigitalIdentities()))
				.setTslLocation(original.getTSLLocation())
				.setSchemeTerritory(getSchemeTerritory(original.getAdditionalInformation()))
				.setTslType(getTSLType(original.getAdditionalInformation()))
				.setMimeType(getMimeType(original.getAdditionalInformation()))
				.setSchemeOperatorNames(getSchemeOperatorNames(original.getAdditionalInformation()))
				.setSchemeTypeCommunityRules(getSchemeTypeCommunityRules(original.getAdditionalInformation()))
				.setMra(getMRA(original.getAdditionalInformation()))
				.build();
	}

	private List<CertificateToken> getCertificates(ServiceDigitalIdentityListType serviceDigitalIdentities) {
		List<CertificateToken> certificates = new ArrayList<>();
		if (serviceDigitalIdentities != null
				&& Utils.isCollectionNotEmpty(serviceDigitalIdentities.getServiceDigitalIdentity())) {
			DigitalIdentityListTypeConverter converter = new DigitalIdentityListTypeConverter();
			for (DigitalIdentityListType digitalIdentityList : serviceDigitalIdentities.getServiceDigitalIdentity()) {
				certificates.addAll(converter.apply(digitalIdentityList));
			}
		}
		return certificates;
	}

	private String getSchemeTerritory(AdditionalInformationType additionalInformation) {
		return getOtherInformationValue(additionalInformation, String.class, SCHEME_TERRITORY);
	}

	private String getTSLType(AdditionalInformationType additionalInformation) {
		return getOtherInformationValue(additionalInformation, String.class, TSL_TYPE);
	}

	private String getMimeType(AdditionalInformationType additionalInformation) {
		return getOtherInformationValue(additionalInformation, String.class, MIME_TYPE);
	}

	private Map<String, List<String>> getSchemeOperatorNames(AdditionalInformationType additionalInformation) {
        InternationalNamesType schemeOperatorNames = getOtherInformationValue(
                additionalInformation, InternationalNamesType.class, SCHEME_OPERATOR_NAME);
        if (schemeOperatorNames != null) {
            return new InternationalNamesTypeConverter().apply(schemeOperatorNames);
        }
		return null;
	}

	private Map<String, List<String>> getSchemeTypeCommunityRules(AdditionalInformationType additionalInformation) {
        NonEmptyMultiLangURIListType schemeTypeCommunityRules = getOtherInformationValue(
                additionalInformation, NonEmptyMultiLangURIListType.class, SCHEME_TYPE_COMMUNITY_RULES);
        if (schemeTypeCommunityRules != null) {
            return new NonEmptyMultiLangURIListTypeConverter().apply(schemeTypeCommunityRules);
        }
		return null;
	}

	private MRA getMRA(AdditionalInformationType additionalInformation) {
		if (mraSupport) {
			MutualRecognitionAgreementInformationType jaxbMRA = getOtherInformationValue(
					additionalInformation, MutualRecognitionAgreementInformationType.class, MRA);
			if (jaxbMRA != null) {
				MRAConverter converter = new MRAConverter();
				return converter.apply(jaxbMRA);
			}
		}
		return null;
	}

    @SuppressWarnings("unchecked")
	private <T extends Serializable> T getOtherInformationValue(AdditionalInformationType additionalInformation, Class<T> targetClass, String elementName) {
		if (additionalInformation != null &&
				Utils.isCollectionNotEmpty(additionalInformation.getTextualInformationOrOtherInformation())) {
			for (Serializable serializableObj : additionalInformation.getTextualInformationOrOtherInformation()) {
				if (serializableObj instanceof AnyType) {
					AnyType anytype = (AnyType) serializableObj;
					List<Object> content = anytype.getContent();
					for (Object objectValue : content) {
						if (objectValue instanceof JAXBElement) {
							JAXBElement<?> jaxbElement = (JAXBElement<?>) objectValue;
							Object value = jaxbElement.getValue();
							if (jaxbElement.getName().getLocalPart().equals(elementName) && targetClass.isInstance(value)) {
								return (T) value;
							}
						}
					}
				}
			}
		}
		return null;
	}

}
