package eu.europa.esig.dss.jades.signature;

import java.util.List;

import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;

public abstract class JAdESExtensionBuilder {

	protected void assertExtensionPossible(JWS jws, boolean isBase64UrlEtsiUComponents) {
		List<Object> etsiU = DSSJsonUtils.getEtsiU(jws);
		if (Utils.isCollectionNotEmpty(etsiU)) {
			if (!DSSJsonUtils.checkComponentsUnicity(etsiU)) {
				throw new DSSException("Extension is not possible, because components of the 'etsiU' header have "
						+ "not common format! Shall be all Strings or Objects.");
			}
			if (DSSJsonUtils.areAllBase64UrlComponents(etsiU) != isBase64UrlEtsiUComponents) {
				throw new DSSException(String.format("Extension is not possible! The encoding of 'etsiU' "
						+ "components shall match! Use jadesSingatureParameters.setBase64UrlEncodedEtsiUComponents(%s)",
						!isBase64UrlEtsiUComponents));
			}
		}
	}

}
