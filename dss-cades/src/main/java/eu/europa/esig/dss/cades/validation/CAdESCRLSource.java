package eu.europa.esig.dss.cades.validation;

import java.util.Collection;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Store;

import eu.europa.esig.dss.validation.CMSCRLSource;
import eu.europa.esig.dss.x509.RevocationOrigin;

@SuppressWarnings("serial")
public class CAdESCRLSource extends CMSCRLSource {

	public CAdESCRLSource(CMSSignedData cmsSignedData, AttributeTable unsignedAttributes) {
		super(cmsSignedData, unsignedAttributes);
	}

	@Override
	protected void collectFromSignedData() {
		final Store<X509CRLHolder> crLs = cmsSignedData.getCRLs();
		final Collection<X509CRLHolder> collection = crLs.getMatches(null);
		for (final X509CRLHolder x509CRLHolder : collection) {
			addX509CRLHolder(x509CRLHolder, RevocationOrigin.INTERNAL_REVOCATION_VALUES);
		}
	}

}
