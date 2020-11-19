package eu.europa.esig.dss.xades.signature;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.reference.DSSTransform;

/**
 * This class represents an extension of {@code Policy} class allowing addition
 * of a custom list of {@code DSSTransform}s to build the ds:Transforms element
 * 
 * NOTE: The digest should be computed by the user and set through the
 * {@code setDigestValue(digestValue)} method
 * 
 * Use {@code DSSXMLUtils.applyTransforms(document, transforms)} in order obtain
 * policy binaries after transforms
 *
 */
public class XmlPolicyWithTransforms extends Policy {

	private static final long serialVersionUID = 8177559439441560945L;

	/**
	 * The list of transforms to be applied on the XML policy before the digest
	 * calculation
	 */
	private List<DSSTransform> transforms;

	public XmlPolicyWithTransforms() {
		super();
	}

	/**
	 * Gets the list of Transforms to incorporate into the signature
	 * 
	 * @return a list of {@link DSSTransform}s
	 */
	public List<DSSTransform> getTransforms() {
		return transforms;
	}

	/**
	 * Sets the list of Transforms to incorporate into the signature
	 * 
	 * @param transforms a list of {@link DSSTransform}s
	 */
	public void setTransforms(List<DSSTransform> transforms) {
		this.transforms = transforms;
	}

	@Override
	public boolean isEmpty() {
		if (!super.isEmpty()) {
			return false;
		}
		if (Utils.isCollectionNotEmpty(transforms)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((transforms == null) ? 0 : transforms.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		XmlPolicyWithTransforms other = (XmlPolicyWithTransforms) obj;
		if (!Objects.equals(transforms, other.transforms)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "XmlPolicyWithTransforms [transforms=" + transforms + ", id()=" + getId() + ", qualifier()="
				+ getQualifier() + ", description()=" + getDescription() + ", documentationReferences()="
				+ Arrays.toString(getDocumentationReferences()) + ", digestAlgorithm()=" + getDigestAlgorithm()
				+ ", digestValue()=" + Arrays.toString(getDigestValue()) + ", spuri()=" + getSpuri() + "]";
	}

}
