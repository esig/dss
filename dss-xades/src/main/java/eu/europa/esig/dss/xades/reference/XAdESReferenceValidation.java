package eu.europa.esig.dss.xades.reference;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.transforms.Transforms;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ReferenceValidation;
import eu.europa.esig.dss.xades.XAdESUtils;

public class XAdESReferenceValidation extends ReferenceValidation {

	private static final long serialVersionUID = 2721340360134442005L;

	private static final Logger LOG = LoggerFactory.getLogger(XAdESReferenceValidation.class);

	private static final Map<String, String> presentableTransformationNames = new HashMap<String, String>();

	static {
		presentableTransformationNames.put(Transforms.TRANSFORM_ENVELOPED_SIGNATURE, "Enveloped Signature Transform");
		presentableTransformationNames.put(Transforms.TRANSFORM_BASE64_DECODE, "Base64 Decoding");
		
		presentableTransformationNames.put(Transforms.TRANSFORM_XPATH2FILTER, "XPath filtering");
		presentableTransformationNames.put(Transforms.TRANSFORM_XPATH, "XPath filtering");
		presentableTransformationNames.put(Transforms.TRANSFORM_XSLT, "XSLT Transform");
		
		presentableTransformationNames.put(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS, "Canonical XML 1.0 with Comments");
		presentableTransformationNames.put(Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS, "Canonical XML 1.1 with Comments");
		presentableTransformationNames.put(Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS, "Exclusive XML Canonicalization 1.0 with Comments");

		presentableTransformationNames.put(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS, "Canonical XML 1.0 (omits comments)");
		presentableTransformationNames.put(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS, "Canonical XML 1.1 (omits comments)");
		presentableTransformationNames.put(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS, "Exclusive Canonical XML (omits comments)");
	}

	/* The digest value of the original document, before applying transformations (if accessible) */
	private final Reference reference;
	/* For XAdES : reference id */
	private final String id;
	/* For XAdES : reference uri */
	private final String uri;
	
	/* List of dependent {@code ReferenceValidation}s (used in case of manifest type for manifest entries) */
	private List<ReferenceValidation> dependentReferenceValidations;
	
	public XAdESReferenceValidation(Reference reference) {
		this.reference = reference;
		this.id = reference.getId();
		this.uri = reference.getURI();
	}
	
	public String getId() {
		return id;
	}
	
	public String getUri() {
		return uri;
	}
	
	/**
	 * Returns original bytes of the referenced document
	 * @return byte array
	 */
	public byte[] getOriginalContentBytes() {
		return XAdESUtils.getReferenceOriginalContentBytes(reference);
	}
	
	@Override
	public String getName() {
		if (Utils.isStringNotBlank(id)) {
			return id;
		} else if (Utils.isStringNotBlank(uri)) {
			return uri;
		}
		return Utils.EMPTY_STRING;
	}
	
	@Override
	public List<ReferenceValidation> getDependentValidations() {
		if (dependentReferenceValidations == null) {
			dependentReferenceValidations = new ArrayList<ReferenceValidation>();
		}
		return dependentReferenceValidations;
	}

	@Override
	public List<String> getTransformationNames() {
		if (transforms == null) {
			transforms = new ArrayList<String>();
			try {
				Transforms referenceTransforms = reference.getTransforms();
				if (referenceTransforms != null) {
					Element transformsElement = referenceTransforms.getElement();
					NodeList transfromChildNodes = transformsElement.getChildNodes();
					if (transfromChildNodes != null && transfromChildNodes.getLength() > 0) {
						for (int i = 0; i < transfromChildNodes.getLength(); i++) {
							Node transformation = transfromChildNodes.item(i);
							if (Node.ELEMENT_NODE == transformation.getNodeType()) {
								transforms.add(buildTransformationName(transformation));
							}
						}
					}
				}
			} catch (XMLSecurityException e) {
				LOG.warn("Unable to analyze trasnformations", e);
			}
		}
		return transforms;
	}
	
	/**
	 * Returns a complete description string for the given transformation node
	 * @param transformation {@link Node} containing a signle reference transformation information
	 * @return transformation description name
	 */
	private String buildTransformationName(Node transformation) {
		String algorithm = DomUtils.getValue(transformation, "@Algorithm");
		if (presentableTransformationNames.containsKey(algorithm)) {
			algorithm = presentableTransformationNames.get(algorithm);
		}
		StringBuilder stringBuilder = new StringBuilder(algorithm);
		if (transformation.hasChildNodes()) {
			NodeList childNodes = transformation.getChildNodes();
			stringBuilder.append(" (");
			boolean hasValues = false;
			for (int j = 0; j < childNodes.getLength(); j++) {
				Node parameterNode = childNodes.item(j);
				if (Node.ELEMENT_NODE != parameterNode.getNodeType()) {
					continue;
				}
				Node parameterValueNode = parameterNode.getFirstChild();
				if (parameterValueNode != null && Node.TEXT_NODE == parameterValueNode.getNodeType() &&
						Utils.isStringNotBlank(parameterValueNode.getTextContent())) {
					if (hasValues) {
						stringBuilder.append("; ");
					}
					stringBuilder.append(parameterNode.getLocalName()).append(": ");
					stringBuilder.append(parameterValueNode.getTextContent());
					hasValues = true;
				}
			}
			stringBuilder.append(")");
		}
		return stringBuilder.toString();
	}

}
