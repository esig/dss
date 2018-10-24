package eu.europa.esig.dss.xades.validation;

import java.util.List;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.w3c.dom.Attr;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.utils.Utils;

/**
 * Resolver for detached signature only.
 * 
 * The reference URI must be null or refer a specific file.
 */
public class DetachedSignatureResolver extends ResourceResolverSpi {

	private final List<DSSDocument> documents;
	private final DigestAlgorithm digestAlgorithm;

	public DetachedSignatureResolver(final List<DSSDocument> documents, DigestAlgorithm digestAlgorithm) {
		this.documents = documents;
		this.digestAlgorithm = digestAlgorithm;
	}

	@Override
	public XMLSignatureInput engineResolveURI(ResourceResolverContext context) throws ResourceResolverException {
		DSSDocument document = getCurrentDocument(context);
		if (document instanceof DigestDocument) {
			DigestDocument digestDoc = (DigestDocument) document;
			return new XMLSignatureInput(digestDoc.getDigest(digestAlgorithm));
		} else {
			final XMLSignatureInput result = new XMLSignatureInput(document.openStream());
			final MimeType mimeType = document.getMimeType();
			if (mimeType != null) {
				result.setMIMEType(mimeType.getMimeTypeString());
			}
			return result;
		}
	}

	private DSSDocument getCurrentDocument(ResourceResolverContext context) throws ResourceResolverException {
		if (definedFilename(context) && isDocumentNamesDefined()) {
			Attr uriAttr = context.attr;
			String uriValue = DSSUtils.decodeUrl(uriAttr.getNodeValue());
			for (DSSDocument dssDocument : documents) {
				if (Utils.areStringsEqual(dssDocument.getName(), uriValue)) {
					return dssDocument;
				}
			}
			Object[] exArgs = { "Unable to find document '" + uriValue + "' (detached signature)" };
			throw new ResourceResolverException("generic.EmptyMessage", exArgs, uriValue, context.baseUri);
		}

		if (Utils.collectionSize(documents) == 1) {
			return documents.get(0);
		}

		Object[] exArgs = { "Unable to find document (detached signature)" };
		throw new ResourceResolverException("generic.EmptyMessage", exArgs, null, context.baseUri);

	}

	@Override
	public boolean engineCanResolveURI(ResourceResolverContext context) {
		return (nullURI(context) || definedFilename(context));
	}

	private boolean nullURI(ResourceResolverContext context) {
		return context.attr == null;
	}

	private boolean definedFilename(ResourceResolverContext context) {
		Attr uriAttr = context.attr;
		return uriAttr != null && Utils.isStringNotBlank(uriAttr.getNodeValue()) && !uriAttr.getNodeValue().startsWith("#");
	}

	private boolean isDocumentNamesDefined() {
		if (Utils.isCollectionNotEmpty(documents)) {
			for (final DSSDocument dssDocument : documents) {
				if (Utils.isStringNotEmpty(dssDocument.getName())) {
					return true;
				}
			}
		}
		return false;
	}

}