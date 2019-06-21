package eu.europa.esig.dss.cades.validation;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSSignedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.validation.CMSOCSPSource;

@SuppressWarnings("serial")
public class CAdESOCSPSource extends CMSOCSPSource {

	CAdESOCSPSource(CMSSignedData cms, AttributeTable unsignedAttributes) {
		super(cms, unsignedAttributes);
	}

}
