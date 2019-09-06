package eu.europa.esig.dss.cades.validation;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSSignedData;

import eu.europa.esig.dss.validation.CMSCRLSource;

@SuppressWarnings("serial")
public class CAdESCRLSource extends CMSCRLSource {

	public CAdESCRLSource(CMSSignedData cmsSignedData, AttributeTable unsignedAttributes) {
		super(cmsSignedData, unsignedAttributes);
	}

}
